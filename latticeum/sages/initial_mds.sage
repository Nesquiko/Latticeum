p = 2 ^ 64 - 2 ^ 32 + 1
F = GF(p)

initial_state = vector(
    F,
    [
        0,
        13458558136629279646,
        11917569669020208757,
        3145715386209370042,
        17331705705982545631,
        13458558136629279646,
        11917569669020208757,
        3145715386209370042,
        17331705705982545631,
        13984430912008153556,
        15521108528102704061,
        4970103052708374450,
        0,
        0,
        0,
        0,
    ],
)


def m_4_4(input_state):
    s_0 = 2 * input_state[0] + 3 * input_state[1] + input_state[2] + input_state[3]
    s_1 = input_state[0] + 2 * input_state[1] + 3 * input_state[2] + input_state[3]
    s_2 = input_state[0] + input_state[1] + 2 * input_state[2] + 3 * input_state[3]
    s_3 = 3 * input_state[0] + input_state[1] + input_state[2] + 2 * input_state[3]

    s_4 = 2 * input_state[4] + 3 * input_state[5] + input_state[6] + input_state[7]
    s_5 = input_state[4] + 2 * input_state[5] + 3 * input_state[6] + input_state[7]
    s_6 = input_state[4] + input_state[5] + 2 * input_state[6] + 3 * input_state[7]
    s_7 = 3 * input_state[4] + input_state[5] + input_state[6] + 2 * input_state[7]

    s_8 = 2 * input_state[8] + 3 * input_state[9] + input_state[10] + input_state[11]
    s_9 = input_state[8] + 2 * input_state[9] + 3 * input_state[10] + input_state[11]
    s_10 = input_state[8] + input_state[9] + 2 * input_state[10] + 3 * input_state[11]
    s_11 = 3 * input_state[8] + input_state[9] + input_state[10] + 2 * input_state[11]

    s_12 = 0
    s_13 = 0
    s_14 = 0
    s_15 = 0

    return [
        s_0,
        s_1,
        s_2,
        s_3,
        s_4,
        s_5,
        s_6,
        s_7,
        s_8,
        s_9,
        s_10,
        s_11,
        s_12,
        s_13,
        s_14,
        s_15,
    ]


def mds_sums(after_m4):
    sum_0 = after_m4[0] + after_m4[4] + after_m4[8] + after_m4[12]
    sum_1 = after_m4[1] + after_m4[5] + after_m4[9] + after_m4[13]
    sum_2 = after_m4[2] + after_m4[6] + after_m4[10] + after_m4[14]
    sum_3 = after_m4[3] + after_m4[7] + after_m4[11] + after_m4[15]

    return [sum_0, sum_1, sum_2, sum_3]


def mds(input_state):
    state_m4 = m_4_4(input_state)
    sums = mds_sums(state_m4)

    return [
        state_m4[0] + sums[0],
        state_m4[1] + sums[1],
        state_m4[2] + sums[2],
        state_m4[3] + sums[3],
        state_m4[4] + sums[0],
        state_m4[5] + sums[1],
        state_m4[6] + sums[2],
        state_m4[7] + sums[3],
        state_m4[8] + sums[0],
        state_m4[9] + sums[1],
        state_m4[10] + sums[2],
        state_m4[11] + sums[3],
        state_m4[12] + sums[0],
        state_m4[13] + sums[1],
        state_m4[14] + sums[2],
        state_m4[15] + sums[3],
    ]


x = (
    +4 * F(0)
    + 6 * F(13458558136629279646)
    + 2 * F(11917569669020208757)
    + 2 * F(3145715386209370042)
    + 2 * F(17331705705982545631)
    + 3 * F(13458558136629279646)
    + F(11917569669020208757)
    + F(3145715386209370042)
    + 2 * F(17331705705982545631)
    + 3 * F(13984430912008153556)
    + F(15521108528102704061)
    + F(4970103052708374450)
)

t_0 = F(2940300425484625778)

print(x)
print(x == t_0)
