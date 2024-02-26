from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import re
import time
from selenium.common.exceptions import WebDriverException

def solve_typing_challenge():
    driver = webdriver.Chrome() 

    try:
        driver.get("https://hacker-typer.tuctf.com")
        time.sleep(5) # just to give the browser time to open

        for _ in range(500): # because 0.1 speed is very fast and skips browser requests I change it to 0.5
            input_element = driver.find_element(By.NAME, "word")
            challenge_info = driver.find_element(By.NAME, "word-title").text
            word_to_type = challenge_info.split(":")[-1].strip()

            print("Word to type:", word_to_type)

            input_element.clear()
            input_element.send_keys(word_to_type)

            time.sleep(0.1) # the speed of the next comming word

            submit_button = driver.find_element(By.CSS_SELECTOR, "form button[type='submit']")
            submit_button.click()

            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.NAME, "status-title")))

            response = driver.find_element(By.NAME, "status-title").text
            print("Response received:", response)

            flag_match = re.search(r'TUCTF{.*?}', response)
            if flag_match:
                flag = flag_match.group()
                print("The flag:", flag)
                break

    except WebDriverException:
        print("WebDriverException error.")

    except Exception as e:
        print(f"Exception error: {e}")

    finally:
        print("")

solve_typing_challenge()
