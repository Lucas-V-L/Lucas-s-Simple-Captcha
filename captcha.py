# Written by Lucas-V-L, relies on at least python 3.7 for ordered dicts

import secrets, time, random, hmac, os
from PIL import Image, ImageDraw, ImageFont, ImageFilter

class Captcha:
    DEFAULT_CHARSET:str="QWERTYUIOPASDFGHJKLZXCVBNM"
    DEFAULT_TIMEOUT:int=3600 # 1 hour, in seconds
    DEFAULT_MIN_TIME:int=1 # acts as a sort of rate limit in seconds, a human cant instantly fill out a form in 0.035 seconds but a robot can
    _DIGEST:str = "sha512"
    _ENCODING:str = "utf-8"
    
    # TODO: write a docstring
    def __init__(self, captcha_length:int, captcha_charset:str=DEFAULT_CHARSET, captcha_timeout:int=DEFAULT_TIMEOUT, captcha_min_time:int=DEFAULT_MIN_TIME):
        self._secret:bytes = secrets.token_bytes(128)
        self._charset:str = captcha_charset
        self._length:int = captcha_length
        self._timeout:int = captcha_timeout
        self._min_time:int = captcha_min_time
        self._invalidated_hashes:dict[str, int] = {"":0}
        
        workdir:str = os.path.dirname(os.path.abspath(__file__))
        self._fonts:list[str] = [workdir + "/fonts/" + i for i in os.listdir(workdir + "/fonts") if i[-4:] == ".ttf"] 

    # TODO: write a docstring - returns a few input elements with the captcha in a div as a string
    def get_captcha(self) -> str:
        epoch:int = int(time.time())
        loophash:str = list(self._invalidated_hashes.keys())[0] # avoids duplicates - very unlikely, but im no gambler.
        while loophash in self._invalidated_hashes:
            randtext:str = "".join([random.choice(self._charset) for i in range(self._length)])
            msghash = hmac.new(self._secret, bytes(randtext + str(epoch), self._ENCODING), self._DIGEST)
            loophash = msghash.hexdigest()

        captchaimg:Image = self.generate_image(randtext, len(randtext) * 40)
        form:str = "<div>"
        form += f"<input type='hidden' name='__CAPTCHA_EPOCH' value='{epoch}'/>"
        form += f"<input type='hidden' name='__CAPTCHA_HASH' value='{loophash}'/>"
        form += "<input type='text' name='__CAPTCHA_TEXT'/>"
        form += "</div>"

        return form

    # TODO: write a docstring - checks the captcha and return true if its correct
    def check_captcha(self, epoch:int, text:str, msghash:str, invalidate:bool=True) -> bool:
        current_epoch:int = int(time.time())

        if (epoch + self._timeout > current_epoch) and \
            (epoch + self._min_time < current_epoch) and \
            not msghash in self._invalidated_hashes and \
            hmac.compare_digest(msghash, hmac.new(self._secret, bytes(text + str(epoch), self._ENCODING), self._DIGEST).hexdigest()): # use compare_digest to avoid timing attacks
                if invalidate: 
                    for i in self._invalidated_hashes:
                        if (self._invalidated_hashes[i] + self._timeout) < current_epoch:
                            del self._invalidated_hashes[i]
                        break
                    self._invalidated_hashes[msghash] = epoch
                return True
        else:
            return False

    def generate_image(self, text:str, width:int=None, height:int=80) -> Image:
        if width == None:
            width = len(text) * height//2
        img:Image = Image.new(mode="LA", size=(width, height), color=(255,255))

        random_grid = tuple((random.randint(185, 255), 255) for i in range(width) for j in range(height))
        img.putdata(random_grid)

        draw:ImageDraw = ImageDraw.Draw(img)
        for i in range(random.randint(13, 16)):
            draw.line([(random.randint(-width//6, width//2),random.randint(-height//2, int(height*1.5))), (random.randint(width//3, int(width*1.2)),random.randint(-height//2, int(height*1.5)))], fill=(0,random.randint(230, 255)), width=random.randint(0, 2))
        counter:int = 0
        step:int = width//len(text)
        for i in range(0, width, step):
            font_size:int = height
            fontpath:str = random.choice(self._fonts)
            font:ImageFont = ImageFont.truetype(fontpath, font_size)

            try: 
                font_width:int = font.getmask(text[counter]).getbbox()[2]
                font_height:int = font.getmask(text[counter]).getbbox()[3] + font.getmetrics()[1]
            except:
                print("font: " + fontpath + " does not contain character " + text[counter] + " remove this character from the charset or remove the font to prevent missing letters!")

            txt=Image.new('LA', (font_width,font_height), (0, 0))
            d = ImageDraw.Draw(txt)
            d.text( (0, 0), text[counter], font=font, fill=(0, random.randint(225,255)) )
            w=txt.rotate(random.randint(-20, 20), expand=1).resize((random.randint(int(step*0.75), step), random.randint(int(height*0.5), height)), Image.NEAREST)
            
            img.paste( w, (i,random.randint(0, height - w.size[-1])), w.split()[-1])
            img = img.convert("L")

            counter += 1

        for i in range(width * height // 10):
            x, y = random.randint(0,width-1), random.randint(0,height-1)
            img.putpixel((x, y), 0 if img.getpixel((x, y)) > 230 else 255)

        img = img.filter(ImageFilter.BoxBlur(0.2))

        img.show()
        return img
    
# only runs if standalone, this is not intended to be a standalone program, so its just tests for development purposes
if __name__ == "__main__":
    captchatest:Captcha = Captcha(5)
    for i in range(6):
        captchatest.generate_image("HELLO")
    input()
    for i in range(3):
        html:str = captchatest.get_captcha()
        print(html)
        text:str = input("Input the requested text: ")
        epochstr:str = "'__CAPTCHA_EPOCH' value='"
        hashstr:str = "'__CAPTCHA_HASH' value='"
        for i in range(5):
            print(captchatest.check_captcha( int(html[html.find(epochstr) + len(epochstr):][:html[html.find(epochstr) + len(epochstr):].find("'/>")]), \
                                             text, \
                                             html[html.find(hashstr) + len(hashstr):][:html[html.find(hashstr) + len(hashstr):].find("'/>")] 
                                            )
                  )
    print(captchatest._invalidated_hashes)

