Name
=============

lua-resty-cms - CMS functions for LuaJIT

Status
======

This library is still under early development and is still experimental.

Description
===========

This library requires an nginx build with [ngx_lua module](https://github.com/openresty/lua-nginx-module), [OpenSSL](https://www.openssl.org), and [LuaJIT 2.0](http://luajit.org/luajit.html).

Synopsis
========

```lua
    # nginx.conf:

    lua_package_path "/path/to/lua-resty-cms/lib/?.lua;;";

    server {
        location = /t {
            content_by_lua_block {
                local cms = require "resty.cms"
                local CMS = cms:new({
                  private_key = "",   -- my pkey for sign or decrypt
                  private_cert = "",  -- my pcert for sign, decrypt or verify
                  public_cert = "",   -- your cert for encrypt
                  root_cert = {},     -- root store for verify
                  algorithm = "RSA-SHA1", -- forget
                  cipher = "des",     -- encrypt cipher
                  method = "ede3_cbc",-- encrypt method
                })
                local signed = CMS:sign("abc")  -- using my pcert and pkey
                ngx.say(CMS:encrypt(signed))    -- using your cert

                -- when I receive your message
                local decrypt = CMS:decrypt(喵喵喵)   -- using my pcert and pkey
                ngx.say(CMS:verify(decrypt))          -- using my pcert and root store
            }
        }
    }
    
```

Methods
=======

To load this library,

1. you need to specify this library's path in ngx_lua's [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive. For example, `lua_package_path "/path/to/lua-resty-rsa/lib/?.lua;;";`.
2. you use `require` to load the library into a local Lua variable:

```lua
    local cms = require "resty.cms"
```

new
---
`syntax: CMS = cms:new()`

Creates a new cms object instance


```lua
-- creates a cms object
local cms = require "resty.cms"
local CMS = cms:new()
```

sign
----
`syntax: signed, err = cms:sign(data)`

verify
------
`syntax: verified, err = cms:verify(data)`

encrypt
------
`syntax: local encryped, err = sm3:encrypt(data)`

decrypt
------
`syntax: local decryped, err = sm3:decrypt(data)`

Author
======

Jianhao Dai (toruneko) <toruneko@outlook.com>


Copyright and License
=====================

This module is licensed under the MIT license.

Copyright (C) 2018, by Jianhao Dai (toruneko) <toruneko@outlook.com>

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


See Also
========
* the ngx_lua module: https://github.com/openresty/lua-nginx-module
