i = var("i")
z0_0, z0_1, z0_2, z0_3 = var("z0_0 z0_1 z0_2 z0_3")
zi_0, zi_1, zi_2, zi_3 = var("zi_0 zi_1 zi_2 zi_3")
acc_0, acc_1, acc_2 = var("acc_0 acc_1 acc_2")

s_0 = 2 * i + 3 * z0_0 + z0_1 + z0_2
s_1 = i + 2 * z0_0 + 3 * z0_1 + z0_2
s_2 = i + z0_0 + 2 * z0_1 + 3 * z0_2
s_3 = 3 * i + z0_0 + z0_1 + 2 * z0_2

s_4 = 2 * z0_3 + 3 * zi_0 + zi_1 + zi_2
s_5 = z0_3 + 2 * zi_0 + 3 * zi_1 + zi_2
s_6 = z0_3 + zi_0 + 2 * zi_1 + 3 * zi_2
s_7 = 3 * z0_3 + zi_0 + zi_1 + 2 * zi_2

s_8 = 2 * zi_3 + 3 * acc_0 + acc_1 + acc_2
s_9 = zi_3 + 2 * acc_0 + 3 * acc_1 + acc_2
s_10 = zi_3 + acc_0 + 2 * acc_1 + 3 * acc_2
s_11 = 3 * zi_3 + acc_0 + acc_1 + 2 * acc_2

s_12 = 0
s_13 = 0
s_14 = 0
s_15 = 0

sum_0 = s_0 + s_4 + s_8 + s_12
sum_1 = s_1 + s_5 + s_9 + s_13
sum_2 = s_2 + s_6 + s_10 + s_14
sum_3 = s_3 + s_7 + s_11 + s_15

sa_0 = s_0 + sum_0
sa_1 = s_1 + sum_1
sa_2 = s_2 + sum_2
sa_3 = s_3 + sum_3

sa_4 = s_4 + sum_0
sa_5 = s_5 + sum_1
sa_6 = s_6 + sum_2
sa_7 = s_7 + sum_3

sa_8 = s_8 + sum_0
sa_9 = s_9 + sum_1
sa_10 = s_10 + sum_2
sa_11 = s_11 + sum_3

sa_12 = s_12 + sum_0
sa_13 = s_13 + sum_1
sa_14 = s_14 + sum_2
sa_15 = s_15 + sum_3

sas = [
    sa_0,
    sa_1,
    sa_2,
    sa_3,
    sa_4,
    sa_5,
    sa_6,
    sa_7,
    sa_8,
    sa_9,
    sa_10,
    sa_11,
    sa_12,
    sa_13,
    sa_14,
    sa_15,
]

for idx, expr in enumerate(sas):
    e = expr.expand().simplify_full()
    print(f"sa_{idx} = {e}")
