local config = {
    attempts = 4,
    idle_weight = 80,
    mine_weight = 10,
    weapon_weight = 10,
    weapon_pool = {1046, 1063, 1075},
}

local function integer_in_range(value, low, high)
    return math.type(value) == "integer" and value >= low and value <= high
end

local function validate(values)
    assert(integer_in_range(values.attempts, 0, 8), "invalid_attack_attempts")
    for _, name in ipairs({"idle_weight", "mine_weight", "weapon_weight"}) do
        assert(integer_in_range(values[name], 0, 100), "invalid_attack_weight")
    end
    assert(values.idle_weight + values.mine_weight + values.weapon_weight == 100,
           "attack_weights_must_sum_to_100")
    assert(type(values.weapon_pool) == "table" and #values.weapon_pool >= 1 and
           #values.weapon_pool <= 8, "invalid_weapon_pool")
    local seen = {}
    for _, card in ipairs(values.weapon_pool) do
        assert(card == 1046 or card == 1063 or card == 1075, "unknown_weapon")
        assert(not seen[card], "duplicate_weapon")
        seen[card] = true
    end
end

local function select_attacks(values, rng)
    validate(values)
    local attacks = {}
    for index = 1, values.attempts do
        local draw = rng(100)
        if draw < values.idle_weight then
            attacks[index] = "idle"
        elseif draw < values.idle_weight + values.mine_weight then
            attacks[index] = "mine"
        else
            attacks[index] = "weapon:" .. values.weapon_pool[rng(#values.weapon_pool) + 1]
        end
    end
    return attacks
end

return {config = config, select_attacks = select_attacks}
