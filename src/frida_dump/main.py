/**
 * Author: sp00f
 * 版权属于我个人所有，你可以转载，但需要标明出处
 * 此文档只用于学习交流目的，用于其他目的本人概不负责
 * 安全既是攻防，希望我所作能对防守的一方提供帮助
 * 各个厂商思路同中有异，我逆向分析仅站在学习者和探测加固强度角度进行，没有针对任何特定厂商
 * 我逆向的版本不是最新版本，甚至我都不知道是哪个版本，请大家多吸取精华，抛弃糟粕
 * 你可以吐槽我，不过还是希望尊重我的辛苦成果，有不对的地方，可以指出，大家互相探讨
 * 对于逆向我也是个小学生，水平有限，还请大佬们一笑而过
 *
*/

import frida
import sys
import os

def read_file_as_str(file_path):
    if not os.path.isfile(file_path):
        raise TypeError(file_path + " does not exist")

    all_the_text = open(file_path).read()
#     print type(all_the_text)
    return all_the_text

def write_messages(message, data):
#     print(message)
    global index 
    print(message['payload'])
    fname =  "d:/dex"  + str(index) +".dex"
    if(message['payload'] == "+INDEX+"):
        fname =  "d:/dex"  + str(index) +".dex"
        index = index + 1
        print fname
    else:
        dexfile = open(fname, "ab+")
        dexfile.write(data)

def hook_define_class():
    hook_js = read_file_as_str("dumdex_open_mem.js")
    #print hook_js
    return hook_js

def main(apk):
    
    device = frida.get_usb_device(10)
    pid = device.spawn([apk])
    session = device.attach(pid)
    device.resume(pid)
    script = session.create_script(hook_define_class())
    script.on('message', write_messages)
    script.load()
    
    
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    index = 0
    main("com.example.hello")

    sys.exit(0)

    