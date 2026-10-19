from zxcvbn import zxcvbn

result = zxcvbn("Tr0ub4dor&3", user_inputs=["edgar", "mandefield"])
print(result["score"])                        # 0 (terrible) to 4 (strong)
print(result["feedback"]["warning"])
print(result["feedback"]["suggestions"])
print(result["crack_times_display"]["offline_slow_hashing_1e4_per_second"])