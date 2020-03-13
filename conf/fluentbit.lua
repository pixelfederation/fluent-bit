function set_index(tag, timestamp, record)
    cluster = "unknown"
    if record["project"] ~= nil then
        record["es_index"] = record["project"]
    end
    if record["type"] ~= nil then
        record["es_index"] = record["es_index"] .. "-" .. record["type"]
    end
    if record["level"] ~= nil then
        record["es_index"] = record["es_index"] .. "-" .. record["level"]
    end
    return 1, timestamp, record
end