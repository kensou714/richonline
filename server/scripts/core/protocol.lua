-- 报文工具：内部协议使用小端序；Lua 二进制字符串可保存 0 字节。
-- 大厅返回 {opcode=外层消息号,payload=二进制}，对局动作返回内部报文字符串数组。
-- 加密、封包、身份验证、整帧发送确认由 EXE 负责，业务脚本只组织明文。
local M = {}
function M.frame(opcode, payload) return { opcode = opcode, payload = payload } end
function M.inner(opcode, game, body) return string.pack("<I2I2", opcode, game) .. (body or "") end
return M
