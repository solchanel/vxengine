print("=== Available vx.* API ===")
for k,v in pairs(vx) do
    print(string.format("  vx.%-25s = %s", k, type(v)))
end
