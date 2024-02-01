import secrets, time, random, hmac

class Captcha:
    DEFAULT_CHARSET:str="QWERTYUIOPASDFGHJKLZXCVBNM23456789" # no 1 or 0 because they look exactly like I and O when distorted
    DEFAULT_TIMEOUT:int=3600 # 1 hour, in seconds
    DEFAULT_MIN_TIME:int=20 # acts as a sort of rate limit in seconds, a human cant instantly fill out a form in 0.035 seconds but a robot can
    _DIGEST:str = "sha512"
    _ENCODING:str = "utf-8"
    
    # TODO: write a docstring
    def __init__(self, captcha_length:int, captcha_charset:str=DEFAULT_CHARSET, captcha_timeout:int=DEFAULT_TIMEOUT, captcha_min_time:int=DEFAULT_MIN_TIME):
        self._secret:bytes = secrets.token_bytes(128)
        self._charset:str = captcha_charset
        self._length:int = captcha_length
        self._timeout:int = captcha_timeout
        self._min_time:int = captcha_min_time

    # TODO: write a docstring - returns a few input elements with the captcha in a div as a string
    def get_captcha(self) -> str:
        epoch:int = int(time.time())
        randtext:str = "".join([random.choice(self._charset) for i in range(self._length)])
        
        msghash = hmac.new(self._secret, bytes(randtext + str(epoch), self._ENCODING), self._DIGEST)

        form:str = "<div>"
        form += f"<input type='hidden' name='__CAPTCHA_EPOCH' value='{epoch}'/>"
        form += f"<input type='hidden' name='__CAPTCHA_HASH' value='{msghash.hexdigest()}'/>"
        form += f"<div>please type \"{randtext}\" into the box</div>"
        form += "<input type='text' name='__CAPTCHA_TEXT'/>"
        form += "</div>"

        return form

    # TODO: write a docstring - checks the captcha and return true if its correct
    def check_captcha(self, epoch:int, text:str, msghash:str) -> bool:
        current_epoch:int = int(time.time())

        return  (epoch + self._timeout > current_epoch) and \
                (epoch + self._min_time < current_epoch) and \
                hmac.compare_digest(msghash, hmac.new(self._secret, bytes(text + str(epoch), self._ENCODING), self._DIGEST).hexdigest()) # use compare_digest to avoid timing attacks

if __name__ == "__main__":
    captchatest:Captcha = Captcha(5)
    html:str = captchatest.get_captcha()
    print(html)
    text:str = input("Input the requested text: ")
    epochstr:str = "'__CAPTCHA_EPOCH' value='"
    hashstr:str = "'__CAPTCHA_HASH' value='"
    print(captchatest.check_captcha( int(html[html.find(epochstr) + len(epochstr):][:html[html.find(epochstr) + len(epochstr):].find("'/>")]), \
                                     text, \
                                     html[html.find(hashstr) + len(hashstr):][:html[html.find(hashstr) + len(hashstr):].find("'/>")] 
                                    )
          )
