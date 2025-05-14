# LePaoReverse
CTBU步道乐跑小程序逆向
## 开头

本来在写脚本代理模拟器，解决位置获取失败的问题，写完后想到之前解包过乐跑小程序的源码，而这次，在请求参数与源码相互对比印证中，我成功找到了参数加密方式与记录上传的流程（当然也少不了AI的帮助）

下面让我一步步讲述这整个过程

### 解密data与sign

![](https://fulian23.oss-cn-beijing.aliyuncs.com/202505120035458.png)

#### data解密

请求体中有`ostype`与`data`

data太常见，直接源码中搜ostype

```js
if ((null === (e = t.header) || void 0 === e ? void 0 : e.flag) && (g = !!t.header.flag), g = t.header.flag, "POST" === t.method) {
    t.header = d(d({}, t.header), {}, {
        "content-type": "application/x-www-form-urlencoded"
    });
    var i = d(d({}, n), t.data),
        a = (0, s.SignMD5)(i, b),
        u = {
            ostype: 5,
            data: (0, s.Encrypt)(JSON.stringify(d(d({}, i), {}, {
                sign: a
            })), v, y)
        };
    t.data = d({}, u)
}

```
源码中发现类似请求，其中`data`参数中的`(0, s.Encrypt)`等价`s.Encrypt`,之后便是加密的数据跟参数

等价于`s.Encrypt(JSON.stringify(t.data+{sign:s.SignMD5(t.data,b)}),o.esk,o.esv)`

可以看出，`data`的数据是加密过后的`t.data`与`sign`，其中`b`是`SignMD5`的参数，`o.esk`、`o.esv`是总的加密`Encrypt`的参数

```js
e.Encrypt = function(t) {
    var e = arguments.length > 1 && void 0 !== arguments[1] ? arguments[1] : u,
        r = arguments.length > 2 && void 0 !== arguments[2] ? arguments[2] : f;
    e = n.default.enc.Utf8.parse(e), r = n.default.enc.Utf8.parse(r);
    var i = n.default.AES.encrypt(t, e, a({
        iv: r
    }, c));
    return i.toString()
}
```

由于传递的参数只有一个`t`，所以`e`为默认的`u`，`r`为默认的`f`

```js
u = function() {
    for (var t = "".split("").reverse().join(""), e = ["W", "e", "t", "2", "C", "8", "d", "3", "4", "f", "6", "2", "n", "d", "i", "3"], r = 0; r < e["gnel".split("").reverse().join("") + "ht".split("").reverse().join("")]; r++) t += e[r];
    return t
}(),
f = function() {
    for (var t = "".split("").reverse().join(""), e = ["K", "6", "i", "v", "8", "5", "j", "B", "D", "8", "j", "g", "f", "3", "2", "D"], r = 0; r < e["gnel".split("").reverse().join("") + "ht".split("").reverse().join("")]; r++) t += e[r];
    return t
}();
```

将代码运行一遍便可得到`Wet2C8d34f62ndi3`与`K6iv85jBD8jgf32D`

回到`Encrypt`函数，`e`应该就是`key`，`r`就是`iv`，加密参数有了

而加密方式就在`c`中

```js
 var c = {
    mode: n.default.mode.CBC,
    padding: n.default.pad.Pkcs7
}
```

![](https://fulian23.oss-cn-beijing.aliyuncs.com/202505120129663.png)

`data`数据解密成功，但是要发送数据还得带上`sign`

#### sign解密

来到`SignMD5`函数

```js
e.SignMD5 = function(t, e) {
    var r = Object.keys(t).sort().reduce((function(e, r) {
        return e + "".concat(r).concat(t[r])
    }), "");
    return l("".concat(r).concat(e))
};
```

这个函数将`t`中的键排序，将排序后的键跟值拼接起来，最后将`r`与`e`拼接起来传递给`l`

```js
function l(t) {
    return n.default.MD5(t).toString()
}
```

而`l`的操作就是返回传递进来字符串的MD5，所以`e`就是加密过程中的盐

```js
e.rd = function() {
    return function() {
        for (var t = "".split("").reverse().join(""), e = ["r", "D", "J", "i", "N", "B", "9", "j", "7", "v", "D", "2"], r = 0; r < e["gnel".split("").reverse().join("") + "ht".split("").reverse().join("")]; r++) t += e[r];
        return t
    }()
}
```

`e`的值也就是传入`SignMD5`的`b`的值，运行后得到`rDJiNB9j7vD2`，写个脚本验证

![](https://fulian23.oss-cn-beijing.aliyuncs.com/202505120154030.png)

解密成功，与此前`sign`一致

至此已经完成了请求的解密与发送

### OSS上传

完成了请求的解密后，继续跟踪后续请求

开始乐跑后会向`/v3/api.php/WpIndex/getOssSts`发送请求，看名字可知是OSS对象存储

会返回OSS对象的凭证与密钥，解密后的data如下：

```json
{
    "SecurityToken":"CAISuAJ1q6Ft5B2yfSjIr5XyL\/bZl5t...qJG+CSAA",
    "AccessKeyId":"STS.NVGdLmzDs53ysrYyDnuJ8mZxV",
    "AccessKeySecret":"EtPzvk9HbaTkJ4ZSxkUr9TPa7RbWnW6WUAunXYjCiAgc",
    "Expiration":"2025-05-11T05:30:13Z",
    "bucket":"lptiyu-data",
    "callback":"eyJjYWxsYmFja1VybC...ybS11cmxlbmNvZGVkIn0="
}
```

当乐跑结束后会向`https://lptiyu-data.oss-cn-hangzhou.aliyuncs.com`发送post

这是将刚才跑步的路程数据上传到aliyun服务器

请求的参数有

```yaml
OSSAccessKeyId: STS.NVGdLmzDs53ysrYyDnuJ8mZxV
signature: MU+NAjvkrszLepVsayH6viLuLxk=
x-oss-security-token: CAISuAJ1q6Ft5B2y...
key: Public/Upload/file/run_record/2025-05-11/853/1746940849871-69.txt
policy: eyJleHBpcmF0aW9uIjoiMjAyNS0wNS0xMVQwN...
file: xx.xx KB
```

对比之前`getOssSts`返回的内容

```js
OSSAccessKeyId --> AccessKeyId
x-oss-security-token --> SecurityToken
key猜测为上传的文件路径
```

来到源码，搜索`OSSAccessKeyId`定位得到

```js
uploadFile({
    url: m,
    filePath: r,
    name: "file",
    formData: {
        key: A,
        policy: y,
        OSSAccessKeyId: l,
        signature: g,
        "x-oss-security-token": h
    }
});
```

除去已经获得的`OSSAccessKeyId`与`x-oss-security-token`，先分析`policy`

#### policy解密

直接提取关键部分

```js
(b = new Date).setHours(b.getHours() + 1)
v = {
    expiration: b.toISOString(),
    conditions: [
        ["content-length-range", 0, 1073741824]
    ]
}
y = a.Base64.encode(JSON.stringify(v))
```

`b`是时间对象为当前时间加一个小时，`v`是一个json对象，有`expiration`与`conditions`，其中`expiration`是`b`转为iso格式的字符串，`conditions`内容固定，最后的`y`值就是将这个json对象base64加密

```json
{"expiration":"2025-05-11T06:20:49.855Z","conditions":[["content-length-range",0,1073741824]]}
```

解密后也确实如此，不过需要注意时区为UTC+00:00

#### key解密

接下来是key的部分

```js
_ = r.split(".").reverse()
w = c(_, 1) 
S = w[0]
A = "".concat(i, "/").concat(Date.now(), "-").concat(Math.floor(150 * Math.random()), ".").concat(S)
//开头字符串
t.next = 2, (0, d.uploadToOSS)(r, "Public/Upload/".concat(o, "/run_record/").concat((0, i.default)().format("YYYY-MM-DD"), "/").concat("".concat(Date.now()).slice(-3)), !0);
```

其实根据发送的内容`Public/Upload/file/run_record/2025-05-11/853/1746940849871-69.txt`可知，最后的`S`是txt，`i`为`Public/Upload/file/run_record/YYYY-MM-DD/后三位(毫秒数)/`

`Math.random()`生成[0,1)之间的数，再用`Math.floor()`向下取整，生成[0,149]的整数，所以生成字符串应为：

`Public/Upload/file/run_record/YYYY-MM-DD/后三位(毫秒数)/当前时间戳-[0,149]随机整数.txt`

#### signature解密

然后是`signature`部分

```js
d = f.AccessKeySecret
在public中已经分析出y的值
g = p(d, y)
p = function(t, e) {
    return o.default.enc.Base64.stringify(o.default.HmacSHA1(e, t))
}
```

可以看出，`signature`的值是将`AccessKeySecret`与`public`的值进行HMAC-SHA1后再base64编码

![](https://fulian23.oss-cn-beijing.aliyuncs.com/202505131418822.png)

与实际值一致

### 乐跑数据绑定

通过以上步骤，乐跑已经完成了对数据的记录与上传，接下来的操作就是对本次的跑步数据与云端的绑定

小程序中是通过`v3/api.php/Run/stopRunV278`接口上传

请求体中的`data`字段解密后如下：

```json
{"uid":1xxxxxx,"token":"F1E404A93D740F31E3B3A9ADDC8749AD","school_id":201,"term_id":1,"course_id":0,"class_id":0,"student_num":"2xxxxxxxxx","card_id":"2xxxxxxxxx","timestamp":1746943887,"version":1,"nonce":"870449","ostype":5,"game_id":2,"start_time":1746942771,"end_time":1746943886,"distance":2.42,"record_img":"","log_data":"[{\"latitude\":29.502963053385418,\"longitude\":106.56841986762153,\"distance\":0.33,\"point_id\":\"4\",\"time\":1746942898,\"longtitude\":106.56841986762153},{\"latitude\":29.50262424045139,\"longitude\":106.5675439453125,\"distance\":0.93,\"point_id\":\"5\",\"time\":1746943141,\"longtitude\":106.5675439453125},{\"latitude\":29.502111273871527,\"longitude\":106.56868679470486,\"distance\":1.72,\"point_id\":\"11\",\"time\":1746943523,\"longtitude\":106.56868679470486}]","file_img":"","is_running_area_valid":1,"mobileDeviceId":1,"mobileModel":"SM-E5260","mobileOsVersion":1,"step_info":"{\"interval\":60,\"list\":[]}","step_num":1,"used_time":1092,"record_file":"run_record/2025-05-11/993/1746943887003-83.txt","sign":"32c2ef7b016840fa0144e743ed3203b5"}
```

响应中的`data`字段解密后如下：

```json
{"record_id":"259xxx","start_time":1746942771,"uid":1xxxxxx,"game_id":2,"time":1092,"distance":2.4199999999999999,"log_num":3,"exp":0,"points":0,"extra_money":0,"record_img":"","prize_list":[],"record_status":0,"record_failed_reason":"当天关联成绩次数已达到上限","calDesc":"消耗了2片面包","calNum":"2","calUrl":"https:\/\/data.lptiyu.com\/Public\/Upload\/pic\/cal_icon\/bread.png","point_list":[{"point_id":"4","longtitude":106.56841986761999,"latitude":29.502963053384999,"point_index":2},{"point_id":"5","longtitude":106.56754394531001,"latitude":29.502624240450999,"point_index":3},{"point_id":"11","longtitude":106.5686867947,"latitude":29.502111273872,"point_index":4}],"pass_tit":"重庆工商大学（兰花湖校区）","pass_intro":"","pass_tips":"","complain_check_status":2}
```

请求体中发现`record_file`，也就是上传到云端的跑步路径，就是在这时候完成了用户本次跑步与云端路径的关联

那既然是直接关联文件，可以重复关联之前的文件吗？

事实上乐跑并没有限制文件的一对一关联，手动构造请求，重复关联同一个文件也是可以的（这也算是乐跑的一点小疏忽）

经过测试，`timestamp`必须为当前时间，`end_time`必须为要在当前时间之前

那`end_time`时间设置成昨天的呢？很遗憾，虽然成绩能上传，但会被当成无效成绩，因为只能上传当天的成绩

### 总结

这次逆向分析，得到了乐跑绑定记录的方式：

从`/v3/api.php/WpIndex/getOssSts`获得OSS的认证信息，再通过`https://lptiyu-data.oss-cn-hangzhou.aliyuncs.com`上传路径数据，最后由`v3/api.php/Run/stopRunV278`绑定云端数据到本次的记录

而`v3/api.php/Run/stopRunV278`上传时只需要保证存在路径文件，也就是说不需要每次都上传路径文件，直接绑定之前的文件也是可以的（不过应该会增加被发现的概率）

![](https://fulian23.oss-cn-beijing.aliyuncs.com/202505141925218.png)

至此，可以手动发包瞬间完成乐跑了✌️
