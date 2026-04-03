"""
Symbolic execution worker using angr.
Provides path exploration (find/avoid), constraint solving for CrackMe targets,
and automatic input recovery.
"""

import json
import sys
import os
import time

def solve_symbolic(request: dict) -> dict:
    """Run angr symbolic exploration."""
    try:
        import angr
        import claripy
    except ImportError:
        return {
            'ok': False,
            'error': 'angr not installed. Install via: pip install angr',
            'setup_hint': 'pip install angr',
        }

    file_path = request.get('file_path', '')
    find_addrs = request.get('find_addresses', [])
    avoid_addrs = request.get('avoid_addresses', [])
    start_addr = request.get('start_address')
    input_length = request.get('input_length', 32)
    timeout_sec = request.get('timeout_sec', 60)
    stdin_mode = request.get('stdin_mode', True)
    argv_mode = request.get('argv_mode', False)

    if not find_addrs:
        return {'ok': False, 'error': 'find_addresses is required (list of target addresses)'}

    t0 = time.time()

    try:
        proj = angr.Project(file_path, auto_load_libs=False)

        # Build symbolic input
        if argv_mode:
            sym_arg = claripy.BVS('argv1', input_length * 8)
            initial_state = proj.factory.entry_state(
                args=[file_path, sym_arg],
                add_options=angr.options.unicorn,
            )
        elif stdin_mode:
            sym_input = claripy.BVS('stdin', input_length * 8)
            initial_state = proj.factory.entry_state(
                stdin=sym_input,
                add_options=angr.options.unicorn,
            )
        else:
            sym_input = None
            initial_state = proj.factory.entry_state(
                add_options=angr.options.unicorn,
            )

        if start_addr:
            addr = int(start_addr, 16) if isinstance(start_addr, str) else start_addr
            initial_state = proj.factory.blank_state(addr=addr, add_options=angr.options.unicorn)

        # Parse addresses
        def parse_addr(a):
            return int(a, 16) if isinstance(a, str) else a

        find_set = [parse_addr(a) for a in find_addrs]
        avoid_set = [parse_addr(a) for a in avoid_addrs]

        simgr = proj.factory.simulation_manager(initial_state)

        simgr.explore(
            find=find_set,
            avoid=avoid_set,
            timeout=timeout_sec,
        )

        elapsed = time.time() - t0

        if simgr.found:
            solutions = []
            for found_state in simgr.found[:5]:  # Limit to 5 solutions
                solution = {}

                # Try to extract input from stdin
                if stdin_mode and 'sym_input' in dir():
                    try:
                        concrete = found_state.solver.eval(sym_input, cast_to=bytes)
                        solution['stdin'] = concrete.decode('latin-1')
                        solution['stdin_hex'] = concrete.hex()
                    except Exception:
                        pass

                # Try to extract from argv
                if argv_mode:
                    try:
                        concrete = found_state.solver.eval(sym_arg, cast_to=bytes)
                        solution['argv1'] = concrete.decode('latin-1')
                        solution['argv1_hex'] = concrete.hex()
                    except Exception:
                        pass

                # Dump all symbolic variables
                try:
                    for var in found_state.solver.all_variables:
                        name = var.args[0] if hasattr(var, 'args') else str(var)
                        try:
                            val = found_state.solver.eval(var, cast_to=bytes)
                            solution[f'var_{name}'] = val.hex()
                        except Exception:
                            pass
                except Exception:
                    pass

                solution['found_at'] = hex(found_state.addr)
                solutions.append(solution)

            return {
                'ok': True,
                'satisfiable': True,
                'solutions': solutions,
                'paths_found': len(simgr.found),
                'paths_deadended': len(simgr.deadended),
                'paths_avoided': len(simgr.avoid) if hasattr(simgr, 'avoid') else 0,
                'elapsed_sec': round(elapsed, 2),
            }
        else:
            return {
                'ok': True,
                'satisfiable': False,
                'solutions': [],
                'paths_found': 0,
                'paths_deadended': len(simgr.deadended),
                'elapsed_sec': round(elapsed, 2),
                'hint': 'No path found to target. Try adjusting find/avoid addresses or increasing timeout.',
            }

    except Exception as e:
        return {
            'ok': False,
            'error': str(e),
            'elapsed_sec': round(time.time() - t0, 2),
        }


def main():
    raw = sys.stdin.read().strip()
    if not raw:
        json.dump({'ok': False, 'error': 'No input'}, sys.stdout)
        return

    request = json.loads(raw)
    action = request.get('action', 'explore')

    file_path = request.get('file_path', '')
    if file_path and not os.path.isfile(file_path):
        json.dump({'ok': False, 'error': f'File not found: {file_path}'}, sys.stdout)
        return

    if action == 'explore':
        result = solve_symbolic(request)
    else:
        result = {'ok': False, 'error': f'Unknown action: {action}'}

    json.dump(result, sys.stdout)


if __name__ == '__main__':
    main()
