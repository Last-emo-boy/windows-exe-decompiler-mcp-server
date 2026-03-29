// @category Analysis
// @description Analyze bounded cross references for function, api, string, or data targets and return JSON

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class AnalyzeCrossReferences extends GhidraScript {

    private static class RelationRecord {
        String functionName;
        String address;
        int depth;
        String relation;
        Set<String> referenceTypes = new LinkedHashSet<>();
        Set<String> referenceAddresses = new LinkedHashSet<>();
        Set<String> matchedValues = new LinkedHashSet<>();
    }

    private static class DirectXrefRecord {
        String fromAddress;
        String type;
        boolean isCall;
        boolean isData;
        String fromFunction;
    }

    private static class PendingFunction {
        Function function;
        int depth;

        PendingFunction(Function function, int depth) {
            this.function = function;
            this.depth = depth;
        }
    }

    private boolean truncated = false;

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private Function resolveFunction(String addressOrSymbol) {
        FunctionManager manager = currentProgram.getFunctionManager();
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressOrSymbol);
            Function byAddress = manager.getFunctionAt(address);
            if (byAddress != null) {
                return byAddress;
            }
            Function byContaining = manager.getFunctionContaining(address);
            if (byContaining != null) {
                return byContaining;
            }
        } catch (Exception ignored) {
        }

        SymbolIterator iterator = currentProgram.getSymbolTable().getSymbols(addressOrSymbol);
        while (iterator.hasNext()) {
            Symbol symbol = iterator.next();
            if (symbol.getSymbolType() != SymbolType.FUNCTION) {
                continue;
            }
            Function bySymbol = manager.getFunctionAt(symbol.getAddress());
            if (bySymbol != null) {
                return bySymbol;
            }
            Function byContaining = manager.getFunctionContaining(symbol.getAddress());
            if (byContaining != null) {
                return byContaining;
            }
        }

        FunctionIterator functions = manager.getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (addressOrSymbol.equals(function.getName())) {
                return function;
            }
        }

        return null;
    }

    private Function resolveFunctionByAddress(String addressString) {
        try {
            Address address = currentProgram.getAddressFactory().getAddress(addressString);
            FunctionManager manager = currentProgram.getFunctionManager();
            Function byAddress = manager.getFunctionAt(address);
            if (byAddress != null) {
                return byAddress;
            }
            return manager.getFunctionContaining(address);
        } catch (Exception ignored) {
            return null;
        }
    }

    private String resolveCallableName(Address address) {
        FunctionManager manager = currentProgram.getFunctionManager();
        Function function = manager.getFunctionAt(address);
        if (function == null) {
            function = manager.getFunctionContaining(address);
        }
        if (function != null) {
            return function.getName();
        }

        Symbol symbol = currentProgram.getSymbolTable().getPrimarySymbol(address);
        if (symbol != null) {
            return symbol.getName();
        }
        return null;
    }

    private String extractStringValue(Data data) {
        if (data == null) {
            return null;
        }

        try {
            StringDataInstance stringData = StringDataInstance.getStringDataInstance(data);
            if (stringData != null) {
                String value = stringData.getStringValue();
                if (value != null && !value.isEmpty()) {
                    return value;
                }
            }
        } catch (Exception ignored) {
        }

        Object value = data.getValue();
        if (value instanceof String) {
            return (String) value;
        }

        String representation = data.getDefaultValueRepresentation();
        if (representation == null || representation.isEmpty() || "?".equals(representation)) {
            return null;
        }
        return representation;
    }

    private Data resolveData(String dataQuery) {
        try {
            Address address = currentProgram.getAddressFactory().getAddress(dataQuery);
            Data direct = currentProgram.getListing().getDefinedDataAt(address);
            if (direct != null) {
                return direct;
            }
            return currentProgram.getListing().getDataContaining(address);
        } catch (Exception ignored) {
            return null;
        }
    }

    private RelationRecord getOrCreateRecord(
        Map<String, RelationRecord> records,
        Function function,
        int depth,
        String relation
    ) {
        String key = function.getEntryPoint().toString() + "|" + relation;
        RelationRecord record = records.get(key);
        if (record != null) {
            if (depth < record.depth) {
                record.depth = depth;
            }
            return record;
        }

        record = new RelationRecord();
        record.functionName = function.getName();
        record.address = function.getEntryPoint().toString();
        record.depth = depth;
        record.relation = relation;
        records.put(key, record);
        return record;
    }

    private void addRecord(
        Map<String, RelationRecord> records,
        Function function,
        int depth,
        String relation,
        String referenceType,
        String referenceAddress,
        String matchedValue,
        int limit
    ) {
        if (!records.containsKey(function.getEntryPoint().toString() + "|" + relation) && records.size() >= limit) {
            truncated = true;
            return;
        }

        RelationRecord record = getOrCreateRecord(records, function, depth, relation);
        if (referenceType != null && !referenceType.isEmpty()) {
            record.referenceTypes.add(referenceType);
        }
        if (referenceAddress != null && !referenceAddress.isEmpty()) {
            record.referenceAddresses.add(referenceAddress);
        }
        if (matchedValue != null && !matchedValue.isEmpty()) {
            record.matchedValues.add(matchedValue);
        }
    }

    private List<RelationRecord> collectDirectCallers(Function function, int depth, int limit) {
        Map<String, RelationRecord> records = new LinkedHashMap<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refsTo.hasNext()) {
            Reference ref = refsTo.next();
            if (!ref.getReferenceType().isCall()) {
                continue;
            }
            Function fromFunction = manager.getFunctionContaining(ref.getFromAddress());
            if (fromFunction == null) {
                continue;
            }
            addRecord(
                records,
                fromFunction,
                depth,
                "caller",
                ref.getReferenceType().getName(),
                ref.getFromAddress().toString(),
                null,
                limit
            );
        }
        return new ArrayList<>(records.values());
    }

    private List<RelationRecord> collectDirectCallees(Function function, int depth, int limit) {
        Map<String, RelationRecord> records = new LinkedHashMap<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        AddressIterator addresses = function.getBody().getAddresses(true);
        while (addresses.hasNext()) {
            Address fromAddress = addresses.next();
            Reference[] refsFrom = currentProgram.getReferenceManager().getReferencesFrom(fromAddress);
            for (Reference ref : refsFrom) {
                if (!ref.getReferenceType().isCall()) {
                    continue;
                }
                Function target = manager.getFunctionAt(ref.getToAddress());
                if (target == null) {
                    target = manager.getFunctionContaining(ref.getToAddress());
                }
                if (target == null) {
                    continue;
                }
                addRecord(
                    records,
                    target,
                    depth,
                    "callee",
                    ref.getReferenceType().getName(),
                    fromAddress.toString(),
                    resolveCallableName(ref.getToAddress()),
                    limit
                );
            }
        }
        return new ArrayList<>(records.values());
    }

    private void collectFunctionGraph(
        Function seed,
        boolean inbound,
        int maxDepth,
        int limit,
        Map<String, RelationRecord> aggregate
    ) {
        Deque<PendingFunction> queue = new ArrayDeque<>();
        Set<String> expanded = new LinkedHashSet<>();
        queue.add(new PendingFunction(seed, 0));

        while (!queue.isEmpty()) {
            PendingFunction pending = queue.removeFirst();
            String expandKey = pending.function.getEntryPoint().toString() + "|" + (inbound ? "in" : "out");
            if (!expanded.add(expandKey)) {
                continue;
            }
            if (pending.depth >= maxDepth) {
                continue;
            }

            List<RelationRecord> direct = inbound
                ? collectDirectCallers(pending.function, pending.depth + 1, limit)
                : collectDirectCallees(pending.function, pending.depth + 1, limit);

            for (RelationRecord relation : direct) {
                String aggregateKey = relation.address + "|" + relation.relation;
                RelationRecord existing = aggregate.get(aggregateKey);
                if (existing == null) {
                  if (aggregate.size() >= limit) {
                      truncated = true;
                      break;
                  }
                  aggregate.put(aggregateKey, relation);
                  existing = relation;
                } else {
                  existing.depth = Math.min(existing.depth, relation.depth);
                  existing.referenceTypes.addAll(relation.referenceTypes);
                  existing.referenceAddresses.addAll(relation.referenceAddresses);
                  existing.matchedValues.addAll(relation.matchedValues);
                }

                if (pending.depth + 1 < maxDepth) {
                    Function related = resolveFunctionByAddress(relation.address);
                    if (related != null) {
                        queue.addLast(new PendingFunction(related, pending.depth + 1));
                    }
                }
            }
        }
    }

    private List<DirectXrefRecord> collectDirectXrefs(Function function, int limit) {
        List<DirectXrefRecord> xrefs = new ArrayList<>();
        FunctionManager manager = currentProgram.getFunctionManager();
        ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(function.getEntryPoint());
        while (refsTo.hasNext()) {
            if (xrefs.size() >= limit) {
                truncated = true;
                break;
            }
            Reference ref = refsTo.next();
            DirectXrefRecord record = new DirectXrefRecord();
            record.fromAddress = ref.getFromAddress().toString();
            record.type = ref.getReferenceType().getName();
            record.isCall = ref.getReferenceType().isCall();
            record.isData = ref.getReferenceType().isData();
            Function fromFunction = manager.getFunctionContaining(ref.getFromAddress());
            record.fromFunction = fromFunction != null ? fromFunction.getName() : null;
            xrefs.add(record);
        }
        return xrefs;
    }

    private void collectApiMatches(String apiNeedle, int limit, Map<String, RelationRecord> inbound) {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            AddressIterator addresses = function.getBody().getAddresses(true);
            while (addresses.hasNext()) {
                Address fromAddress = addresses.next();
                Reference[] refsFrom = currentProgram.getReferenceManager().getReferencesFrom(fromAddress);
                for (Reference ref : refsFrom) {
                    if (!ref.getReferenceType().isCall()) {
                        continue;
                    }
                    String calleeName = resolveCallableName(ref.getToAddress());
                    if (calleeName == null) {
                        continue;
                    }
                    if (!calleeName.toLowerCase(Locale.ROOT).contains(apiNeedle)) {
                        continue;
                    }
                    addRecord(
                        inbound,
                        function,
                        1,
                        "api_call",
                        ref.getReferenceType().getName(),
                        fromAddress.toString(),
                        calleeName,
                        limit
                    );
                }
            }
        }
    }

    private void collectStringMatches(String stringNeedle, int limit, Map<String, RelationRecord> inbound) {
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        FunctionManager manager = currentProgram.getFunctionManager();
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            String value = extractStringValue(data);
            if (value == null || !value.toLowerCase(Locale.ROOT).contains(stringNeedle)) {
                continue;
            }

            ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
            while (refsTo.hasNext()) {
                Reference ref = refsTo.next();
                Function function = manager.getFunctionContaining(ref.getFromAddress());
                if (function == null) {
                    continue;
                }
                addRecord(
                    inbound,
                    function,
                    1,
                    "string_reference",
                    ref.getReferenceType().getName(),
                    ref.getFromAddress().toString(),
                    value,
                    limit
                );
            }
        }
    }

    private String collectDataMatches(String dataQuery, int limit, Map<String, RelationRecord> inbound) {
        Data data = resolveData(dataQuery);
        if (data == null) {
            return null;
        }

        String value = extractStringValue(data);
        ReferenceIterator refsTo = currentProgram.getReferenceManager().getReferencesTo(data.getAddress());
        FunctionManager manager = currentProgram.getFunctionManager();
        while (refsTo.hasNext()) {
            Reference ref = refsTo.next();
            Function function = manager.getFunctionContaining(ref.getFromAddress());
            if (function == null) {
                continue;
            }
            addRecord(
                inbound,
                function,
                1,
                "data_reference",
                ref.getReferenceType().getName(),
                ref.getFromAddress().toString(),
                value == null ? data.getAddress().toString() : value,
                limit
            );
        }

        return data.getAddress().toString();
    }

    private void appendStringArray(StringBuilder sb, Set<String> values) {
        sb.append('[');
        boolean first = true;
        for (String value : values) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escapeJson(value)).append('"');
        }
        sb.append(']');
    }

    private void appendRelationArray(StringBuilder sb, Map<String, RelationRecord> relations) {
        List<RelationRecord> ordered = new ArrayList<>(relations.values());
        ordered.sort(
            Comparator
                .comparingInt((RelationRecord item) -> item.depth)
                .thenComparing(item -> item.functionName == null ? "" : item.functionName)
                .thenComparing(item -> item.address == null ? "" : item.address)
        );

        sb.append('[');
        boolean first = true;
        for (RelationRecord relation : ordered) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('{');
            sb.append("\"function\":\"").append(escapeJson(relation.functionName)).append("\",");
            sb.append("\"address\":\"").append(escapeJson(relation.address)).append("\",");
            sb.append("\"depth\":").append(relation.depth).append(',');
            sb.append("\"relation\":\"").append(escapeJson(relation.relation)).append("\",");
            sb.append("\"reference_types\":");
            appendStringArray(sb, relation.referenceTypes);
            sb.append(",\"reference_addresses\":");
            appendStringArray(sb, relation.referenceAddresses);
            sb.append(",\"matched_values\":");
            appendStringArray(sb, relation.matchedValues);
            sb.append('}');
        }
        sb.append(']');
    }

    private void appendDirectXrefs(StringBuilder sb, List<DirectXrefRecord> xrefs) {
        sb.append('[');
        boolean first = true;
        for (DirectXrefRecord record : xrefs) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('{');
            sb.append("\"from_address\":\"").append(escapeJson(record.fromAddress)).append("\",");
            sb.append("\"type\":\"").append(escapeJson(record.type)).append("\",");
            sb.append("\"is_call\":").append(record.isCall).append(',');
            sb.append("\"is_data\":").append(record.isData);
            if (record.fromFunction != null) {
                sb.append(",\"from_function\":\"").append(escapeJson(record.fromFunction)).append("\"");
            }
            sb.append('}');
        }
        sb.append(']');
    }

    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            println("{\"error\":\"No program loaded\"}");
            return;
        }

        String[] args = getScriptArgs();
        if (args.length < 4) {
            println("{\"error\":\"Usage: AnalyzeCrossReferences.java <target_type> <query> <depth> <limit>\"}");
            return;
        }

        String targetType = args[0];
        String query = args[1];
        int depth = Integer.parseInt(args[2]);
        int limit = Integer.parseInt(args[3]);

        if (depth < 1) {
            depth = 1;
        }
        if (limit < 1) {
            limit = 1;
        }

        Map<String, RelationRecord> inbound = new LinkedHashMap<>();
        Map<String, RelationRecord> outbound = new LinkedHashMap<>();
        List<DirectXrefRecord> directXrefs = new ArrayList<>();
        String resolvedAddress = null;
        String resolvedName = null;

        if ("function".equalsIgnoreCase(targetType)) {
            Function targetFunction = resolveFunction(query);
            if (targetFunction == null) {
                println("{\"error\":\"Function not found: " + escapeJson(query) + "\"}");
                return;
            }
            resolvedAddress = targetFunction.getEntryPoint().toString();
            resolvedName = targetFunction.getName();
            collectFunctionGraph(targetFunction, true, depth, limit, inbound);
            collectFunctionGraph(targetFunction, false, depth, limit, outbound);
            directXrefs = collectDirectXrefs(targetFunction, Math.min(limit, 40));
        } else if ("api".equalsIgnoreCase(targetType)) {
            collectApiMatches(query.toLowerCase(Locale.ROOT), limit, inbound);
        } else if ("string".equalsIgnoreCase(targetType)) {
            collectStringMatches(query.toLowerCase(Locale.ROOT), limit, inbound);
        } else if ("data".equalsIgnoreCase(targetType)) {
            resolvedAddress = collectDataMatches(query, limit, inbound);
            if (resolvedAddress == null) {
                println("{\"error\":\"Data target not found: " + escapeJson(query) + "\"}");
                return;
            }
        } else {
            println("{\"error\":\"Unsupported target_type: " + escapeJson(targetType) + "\"}");
            return;
        }

        StringBuilder sb = new StringBuilder(16384);
        sb.append('{');
        sb.append("\"target_type\":\"").append(escapeJson(targetType.toLowerCase(Locale.ROOT))).append("\",");
        sb.append("\"target\":{");
        sb.append("\"query\":\"").append(escapeJson(query)).append("\"");
        if (resolvedAddress != null) {
            sb.append(",\"resolved_address\":\"").append(escapeJson(resolvedAddress)).append("\"");
        }
        if (resolvedName != null) {
            sb.append(",\"resolved_name\":\"").append(escapeJson(resolvedName)).append("\"");
        }
        sb.append("},");
        sb.append("\"inbound\":");
        appendRelationArray(sb, inbound);
        sb.append(",\"outbound\":");
        appendRelationArray(sb, outbound);
        sb.append(",\"direct_xrefs\":");
        appendDirectXrefs(sb, directXrefs);
        sb.append(",\"truncated\":").append(truncated);
        sb.append(",\"limits\":{");
        sb.append("\"depth\":").append(depth).append(',');
        sb.append("\"limit\":").append(limit);
        sb.append("}}");
        println(sb.toString());
    }
}
