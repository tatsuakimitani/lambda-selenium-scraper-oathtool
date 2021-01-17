import os
import json
import glob
import random
import time
import datetime
import logging
import traceback

import oathtool

from slack import WebClient
from slack.errors import SlackApiError

import boto3
import base64
from botocore.exceptions import ClientError

# selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By 
from selenium.webdriver.support.ui import WebDriverWait 
from selenium.webdriver.support import expected_conditions as EC 
from selenium.common.exceptions import TimeoutException 
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import Select
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys

# set up Logger
import logging
import sys
logger = logging.getLogger()
for h in logger.handlers:
    logger.removeHandler(h)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter(
    '%(levelname)s %(asctime)s [%(funcName)s] %(message)s'))
logger.addHandler(handler)
logger.setLevel(logging.INFO)
#logger.setLevel(logging.DEBUG)

# set up constants

def set_selenium_options():
    """ Set selenium options """
    logging.info("Seleniumオプションをセットします。")
    options = Options()
    options.binary_location = '/opt/headless-chromium'
    options.add_argument('--headless')
    options.add_argument('--window-size=2560,2048')
    options.add_argument('--no-sandbox')
    options.add_argument('--single-process')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument("--homedir=/tmp")

    return webdriver.Chrome('/opt/chromedriver', chrome_options=options)


def wait_until_element_present(driver, key, location):
    """ Wait until element is presented at location """
    elm = None
    counter = 0
    timeup = 10
    while counter < timeup:
        try:
            elm = WebDriverWait(driver, counter).until(
                EC.presence_of_element_located((key, location)))
        except NoSuchElementException as e:
            logger.warn("[WARN] {e}".format(e=e))
            logger.warn("counter: {val}".format(val=counter))
            counter += 1 
            continue
        except TimeoutException as e:
            logger.warn("[WARN] {e}".format(e=e))
            logger.warn("counter: {val}".format(val=counter))
            counter += 1
            continue
        else:
            break
    
    return elm

def get_text_by_xpath(driver, location):
    return driver.find_element_by_xpath(location).text


def save_screenshot(driver, filename):
    """ Save screenshot at Amazon S3 """
    logging.info("SS取得を開始します。")
    driver.save_screenshot("/tmp/" + filename)
    logging.info("SS取得を完了しました。")
    return


def terminate_driver(driver):
    """ Terminate driver """
    driver.close()
    driver.quit()
    return

def get_otp():
    """ get One Time Password """
    logging.info("OTP取得を開始します。")
    secret_key = MFA_SECRET_NAME
    secret_info = get_secret(secret_key)
    secret = secret_info.get(MFA_SECRET_KEY)
    otp = oathtool.generate_otp(secret)
    logging.info("OTP取得を完了しました。")
    return otp

def post_slack():
    """ POST to slack """
    logging.info("slack通知を開始します。")
    # APIトークンを指定
    secret_key = SLACK_BOT_SECRET_NAME
    secret_info = get_secret(secret_key)
    token = secret_info.get(SLACK_BOT_SECRET_KEY)
    client = WebClient(token=token)

    # アップロードするチャンネルを指定
    channel = SLACK_CHANNEL

    try:
        response = client.chat_postMessage(
            channel=channel,
            text="Emergency Alert <@channel>")
    except SlackApiError as e:
        # You will get a SlackApiError if "ok" is False
        assert e.response["ok"] is False
        assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
        logger.error("[ERROR] Got an error: " + {e.response['error']})

    thread_ts = response["ts"]
    # 絶対パスを指定
    files = glob.glob('/tmp/*.png')

    # 複数ファイルアップロードはslackAPIはサポート外
    for file in files:
        try:
            response = client.files_upload(
                channels=channel,
                file=file,
                thread_ts=thread_ts)
            assert response["file"]  # the uploaded file
            logging.debug(file + "をslackへ投稿しました。")
        except SlackApiError as e:
            # You will get a SlackApiError if "ok" is False
            assert e.response["ok"] is False
            assert e.response["error"]  # str like 'invalid_auth', 'channel_not_found'
            logger.error("[ERROR] Got an error: " + {e.response['error']})
    logging.info("slack通知が終了しました")

def get_secret(secret_name):
    logging.info("get aws secret key")

    # Create a Secrets Manager client
    session = boto3.session.Session()
    region = session.region_name
    client = session.client(
        service_name='secretsmanager',
        region_name=region
    )
    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.
    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    
    secret = json.loads(get_secret_value_response.get('SecretString'))
    logging.info(secret_name + "を取得しました。")
        
    return secret

def delete_local_screenshot():
    """ delete local screenshot """
    files = glob.glob('/tmp/*.png')
    for file in files:
        os.remove(file)
        logging.debug(file + 'を削除しました。')    
    logging.info('スクリーンショットを削除しました。')    

def main(event, context):
    """ Entrypoint of lambda """
    otp = get_otp()
    
    # Debug event to CloudWatch log
    starttime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    logging.info("starttime: {}".format(starttime))
    logging.info(json.dumps(event))

    driver = None
    target = None
    url = LOGIN_TARGET_URL
    login_info = get_secret(LOGIN_INFO_SECRET_NAME)
    login_id = login_info.get('username')
    login_pw = login_info.get('password')
    logging.info(login_id)

    try:        
        logging.info( url + "へアクセスします。")
        driver = set_selenium_options()
        driver.maximize_window()
        logging.info("ログインページへアクセスします。")
        driver.get(url)
        presented = wait_until_element_present(
            driver, By.ID, LOGIN_LOCATION)
        
        logging.info("ログインページへアクセスしました。")
        input_id = driver.find_element_by_name('username')
        input_password = driver.find_element_by_name('password')
        input_id.send_keys(login_id)
        input_password.send_keys(login_pw)
        button_login = driver.find_element_by_class_name('buttoninput')
        logging.info("ログインボタンを押下します。")
        
        button_login.click()
        presented = wait_until_element_present(
            driver, By.ID, MFA_PAGE_LOCATION)

        logging.info("ログインに成功しました。MFAコードを入力します。")
        second_pass = get_otp()
        second_input_pass = driver.find_element_by_id('mfacode')
        second_input_pass.send_keys(second_pass)
        logging.info("MFA送信ボタンを押下します。")

        second_button_login = driver.find_element_by_class_name('css3button')
        second_button_login.click()

        presented = wait_until_element_present(
            driver, By.XPATH, CONSOLE_LOCATION)
        logging.info("コンソールへのログインに成功しました。")

        # CloudWatchダッシュボードへアクセス
        driver.get(DASHBOARD_URL)
        presented = wait_until_element_present(
            driver, By.ID, DASHBOARD_LOCATION)
        
        filename = 'ss_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S' + '.png')
        save_screenshot(driver, filename)
        if presented is not None:
            target = driver.find_element_by_xpath(DASHBOARD_LOCATION).text

        # PerformanceInsightへアクセス
        driver.get(PI_URL)
        presented = wait_until_element_present(
            driver, By.XPATH, PI_LOCATION)
        change_duration_button = driver.find_element_by_xpath(PI_LOCATION)
        change_duration_button.click()
        driver.implicitly_wait(20)

        filename = 'ss_' + datetime.datetime.now().strftime('%Y%m%d_%H%M%S' + '.png')
        save_screenshot(driver, filename)
        if presented is not None:
            target = driver.find_element_by_xpath(PI_LOCATION).text

        post_slack()

        delete_local_screenshot()
        endtime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.info("endtime: {}".format(endtime))
        terminate_driver(driver)
        return {
            "statusCode": 200,
            "body": target
        }
    except Exception as e:
        logger.error("[ERROR] {e}".format(e=e))
        delete_local_screenshot()
        terminate_driver(driver)
        return {
            "statusCode": 400,
            "body": e
        }