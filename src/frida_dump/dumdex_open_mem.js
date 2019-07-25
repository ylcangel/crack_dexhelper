/**
 * Author: sp00f
 * 版权属于我个人所有，你可以转载，但需要标明出处
 * 此文档只用于学习交流目的，用于其他目的本人概不负责
 * 安全既是攻防，希望我所作能对防守的一方提供帮助
 * 各个厂商思路同中有异，我逆向分析仅站在学习者和探测加固强度角度进行，没有针对任何特定厂商
 * 我逆向的版本不是最新版本，甚至我都不知道是哪个版本，请大家多吸取精华，抛弃糟粕
 * 你可以吐槽我，不过还是希望尊重我的辛苦成果，有不对的地方，可以指出，大家互相探讨
 * 对于逆向我也是个小学生，水平有限，还请大佬们一笑而过
 * 注意：
 * 已经经过测试，可以把拆分的所有dex都脱出来
 * 切记只能在安装后运行第一次才能有效
 * 他家的加固，只有第一次内存的dex是完整的，后续他们对内存中的dex进行了处理
 * 导致你后面dump出来的都是没有code的
*/

function dump(dp, fsize) {
	var mapx_buf_len = 10240;
	var i = 0;
	var count = parseInt(fsize / mapx_buf_len);
	var lastbuf_len = parseInt(fsize % mapx_buf_len);
	
	if (lastbuf_len > 0) {
		count += 1;
	} 
	
	console.log("[+] send count: " + count);
	console.log("[+] send lastbuf_len: " + lastbuf_len);
	
	for (; i < count ; i++) {
		if ((lastbuf_len > 0) && (i == (count - 1))) {
			console.log("[*] mem off: " + i*mapx_buf_len);
			console.log("[*] mem last off: " + lastbuf_len);
			send("Send dex file", Memory.readByteArray(ptr(dp + i*mapx_buf_len) , lastbuf_len));
		}  else {
			console.log("[*] mem off: " + i*mapx_buf_len);
			send("Send dex file", Memory.readByteArray(ptr(dp + i*mapx_buf_len) , mapx_buf_len));
		} 
	}
}

var match_str = ".cache/classes.jar";
var is_matched = false;
var dumped_dex = [];
var location;
/* static const DexFile* DexFile::OpenMemory(const byte* base,
	   size_t size,
	   const std::string& location,
	   uint32_t location_checksum,
	   MemMap* mem_map, std::string* error_msg) */

// 5.02 export sym
// _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPS9_
// you should change next line for your android version
var OpenMemory = Module.findExportByName("libart.so", "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPS9_");
// you should change up line for your android version
console.log("[*] OpenMemory method addr: " + OpenMemory);
Interceptor.attach(OpenMemory, {
	onEnter: function (args) {
		location = ptr(args[2].add(0x8).readUInt()).readUtf8String();
		
		if(location.match(match_str) == match_str) {
			console.log("[*] dex location = " + location);
			is_matched = true;
		}
	},
	onLeave: function (retval) {
		
 		var is_dumped = false;
		var i = 0;
		for (; i < dumped_dex.length; i++) {
			if(location.match(dumped_dex[i]) == location) {
				is_dumped = true;
				break;
			}
		}
		
		if(!is_dumped) {
			// momery:ACB22380  0xB4DF9240 // vt
			// momery:ACB22384  0xA3B78000 // begin
			// momery:ACB22388  0x587358   // size

			if (is_matched) {
				send("+INDEX+")
				console.log("[*] begin to dump dex ...");
				var dex_begin = retval.add(4).readUInt();
				var dex_size = retval.add(8).readInt();
				console.log("[*] dex begin = " + dex_begin + ", dex size = " + ptr(dex_size));
				
				console.log(Memory.readByteArray(ptr(dex_begin), 64));
				dump(dex_begin, dex_size);
				is_matched = false;
				
				dumped_dex.push(location);
				console.log("[*] leave to dump dex ...");
			}
		}
	}
});

