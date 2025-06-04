-- CTCaer's Joy-Con BT over USB protocol dissect script for Wireshark
-- Version 0.9
-- This is provided as is. No license. :)
p_bthid_jc = Proto ("Joycon","Joy-Con HID over BT")
local f_rpt_type = ProtoField.uint8("bthid.jc.src", "Report Type", base.HEX)
local f_command = ProtoField.uint8("bthid.jc.cmd", "Command", base.HEX)
local f_inputid = ProtoField.uint8("bthid.jc.inputid", "id", base.HEX)
local f_lol = ProtoField.uint8("bthid.jc.lol", "test", base.HEX)
local f_subcommand = ProtoField.uint8("bthid.jc.sub", "Subcommand", base.HEX)
local f_timming = ProtoField.uint8("bthid.jc.time", "Timming byte", base.HEX)
local f_subcommandjoy = ProtoField.uint8("bthid.jc.sub2", "Sub cmd ack", base.HEX)
local f_rumble = ProtoField.uint64("bthid.jc.rumble", "Vibration pattern", base.HEX)

p_bthid_jc.fields = {f_lol, f_rpt_type, f_command, f_inputid, f_subcommand, f_subcommandjoy, f_timming, f_rumble}

function p_bthid_jc.dissector (buf, pkt, root)
  --Check for no bt packet or JC/Host reply
  if buf:len() == 0 then return end
  local jc_host_check = buf(0,1):uint() == 0xa1 or buf(0,1):uint() == 0xa2
  if not jc_host_check then return end
  pkt.cols.protocol = p_bthid_jc.name
 
  subtree = root:add(p_bthid_jc, buf(0))
  --Joy-Con packet
  if buf(0,1):uint() == 0xa1
    then 
      subtree:add(f_rpt_type, buf(0,1))
      subtree:add(f_inputid, buf(1,1))
      subtree:add(f_timming, buf(2,1))

	  local info = buf(3, 1)
	  local buttons = buf(4, 3)
	  local lstick = buf(7, 3)
	  local rstick = buf(10, 3)
	  local vibrator = buf(13, 1)

      --check if it's a 0x21 input report
	  if buf(1,1):uint() == 0x21 then
		  --If reply type byte is > 0x80, thenn it's an ACK
		  --param = buf(16)
		  local switch_reply_type = buf(14,1):uint()
		  local switch_ack_subcmd = buf(15,1):uint()
		  local switch_controller_type = "Pro Controller"

		  if switch_reply_type == 0x82 then
			  pkt.cols.info = "Device info"
			  if buf(18,1):uint() == 0x01 then
				  switch_controller_type = "Left Joy-Conn"
			  elseif buf(18,1):uint() == 0x02 then
				  switch_controller_type = "Right Joy-Conn"
			  elseif buf(18,1):uint() == 0x03 then
				  switch_controller_type = "Por Controller"
			  end
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(),
			  string.format("Subcmd reply: 0x02 [Device info], %s, FW Version: %X.%02x, MAC Addr: %02x:%02x:%02x:%02x:%02x:%02x",
			  switch_controller_type, buf(16,1):uint(), buf(17,1):uint(), buf(20,1):uint(), buf(21,1):uint(), buf(22,1):uint(), buf(23,1):uint(), buf(24,1):uint(), buf(25,1):uint()))
		  elseif switch_reply_type == 0x90 then
			  pkt.cols.info = "SPI Read data reply"
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(), "Subcmd reply: 0x10 [SPI Read data]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x08 then
			  pkt.cols.info = "Shipment set ACK"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), "Subcmd reply: 0x08 [Shipment set ACK]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x03 then
			  pkt.cols.info = "Input Report Format set ACK"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), "Subcmd reply: 0x03 [Input Report Format set ACK]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x11 then
			  pkt.cols.info = "SPI Write OK"
			  subtree:add(f_subcommandjoy, buf(15,1), buf(15,1):uint(), "Subcmd reply: 0x11 [SPI Write ACK]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x05 then
			  pkt.cols.info = "Page Info"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), string.format("Subcmd reply: 0x05 [Page Info], Arg: 0x%02x", buf(24,1):uint()))
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x22 then
			  pkt.cols.info = "MCU Resume ACK"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), "Subcmd reply: 0x22 [MCU Resume ACK]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x40 then
			  pkt.cols.info = "6-Axis Enable set ACK"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), "Subcmd reply: 0x40 [6-Axis Enable set ACK]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x48 then
			  pkt.cols.info = "Vibration Enable set ACK"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), "Subcmd reply: 0x48 [Vibration Enable set ACK]")
		  elseif switch_reply_type == 0x80 and switch_ack_subcmd == 0x30 then
			  pkt.cols.info = "Player Lights set ACK"
			  subtree:add(f_subcommandjoy, buf(14,2), buf(14,2):uint(), "Subcmd reply: 0x30 [Player Lights set ACK]")
		  elseif switch_reply_type == 0x81 then
			  pkt.cols.info = "Pairing IN"
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(),
			  string.format("Subcmd reply: 0x01 [Pairing IN], Arg: %08x %08x %08x %08x %08x %08x %08x %08x %04x",
			  buf(16,4):uint(), buf(20,4):uint(), buf(24,4):uint(), buf(28,4):uint(), buf(32,4):uint(), buf(36,4):uint(), buf(40,4):uint(), buf(44,4):uint(), buf(48,2):uint()))
		  elseif switch_reply_type == 0xA0 then
			  pkt.cols.info = "MCU Config data reply"
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(),
			  string.format("Subcmd reply: 0x21 [MCU Config data], Arg: %08x %08x %08x %08x %08x %08x %08x %08x %04x",
			  buf(16,4):uint(), buf(20,4):uint(), buf(24,4):uint(), buf(28,4):uint(), buf(32,4):uint(), buf(36,4):uint(), buf(40,4):uint(), buf(44,4):uint(), buf(48,2):uint()))
		  elseif switch_reply_type == 0xA8 then
			  pkt.cols.info = "Attachment data "
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(),
			  string.format("Subcmd reply: 0x28? [Attachment data], Arg: %08x %08x %08x %08x %08x %08x %08x %08x %04x",
			  buf(16,4):uint(), buf(20,4):uint(), buf(24,4):uint(), buf(28,4):uint(), buf(32,4):uint(), buf(36,4):uint(), buf(40,4):uint(), buf(44,4):uint(), buf(48,2):uint()))
		  elseif switch_reply_type == 0xc0 then
			  pkt.cols.info = "Sensor data"
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(),
			  string.format("Subcmd reply: 0x41 [Sensor data], Arg: %08x %08x %08x %08x %08x %08x %08x %08x %04x",
			  buf(16,4):uint(), buf(20,4):uint(), buf(24,4):uint(), buf(28,4):uint(), buf(32,4):uint(), buf(36,4):uint(), buf(40,4):uint(), buf(44,4):uint(), buf(48,2):uint()))
		  elseif switch_reply_type == 0x83 then
			  pkt.cols.info = "L\\R Elapsed time"
			  local time1 = 10 * bit.bor(bit.lshift(buf(17,1):uint(), 8), buf(16,1):uint())
			  local time2 = 10 * bit.bor(bit.lshift(buf(19,1):uint(), 8), buf(18,1):uint())
			  local time3 = 10 * bit.bor(bit.lshift(buf(21,1):uint(), 8), buf(20,1):uint())
			  local time4 = 10 * bit.bor(bit.lshift(buf(23,1):uint(), 8), buf(22,1):uint())
			  local time5 = 10 * bit.bor(bit.lshift(buf(25,1):uint(), 8), buf(24,1):uint())
			  local time6 = 10 * bit.bor(bit.lshift(buf(27,1):uint(), 8), buf(26,1):uint())
			  local time7 = 10 * bit.bor(bit.lshift(buf(29,1):uint(), 8), buf(28,1):uint())
			  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(),
			  string.format("Subcmd reply: 0x04 [L\\R Elapsed time], L: %dms, R: %dms, ZL: %dms, ZR: %dms, SL: %dms, SR: %dms, HOME: %dms", time1, time2, time3, time4, time5, time6, time7))
		  elseif switch_reply_type > 0x7F then 
			  subtree:add(f_subcommandjoy,buf(14,2))
		  end

	  elseif buf(1,1):uint() == 0x3f or buf(1,1):uint() == 0x30 then
		  local btn = buttons(0, 3):uint()
		  local str = string.format("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s vibrator %02x",
		  (bit.band(btn, 0x010000) ~= 0) and " Y" or "",
		  (bit.band(btn, 0x020000) ~= 0) and " X" or "",
		  (bit.band(btn, 0x040000) ~= 0) and " B" or "",
		  (bit.band(btn, 0x080000) ~= 0) and " A" or "",
		  (bit.band(btn, 0x100000) ~= 0) and " SR" or "",
		  (bit.band(btn, 0x200000) ~= 0) and " SL" or "",
		  (bit.band(btn, 0x400000) ~= 0) and " R" or "",
		  (bit.band(btn, 0x800000) ~= 0) and " ZR" or "",
		  (bit.band(btn, 0x000100) ~= 0) and " Minus" or "",
		  (bit.band(btn, 0x000200) ~= 0) and " Plus" or "",
		  (bit.band(btn, 0x000400) ~= 0) and " Rs" or "",
		  (bit.band(btn, 0x000800) ~= 0) and " Ls" or "",
		  (bit.band(btn, 0x001000) ~= 0) and " Home" or "",
		  (bit.band(btn, 0x002000) ~= 0) and " Capture" or "",
		  (bit.band(btn, 0x004000) ~= 0) and " --" or "",
		  (bit.band(btn, 0x008000) ~= 0) and " Charging" or "",
		  (bit.band(btn, 0x000001) ~= 0) and " Down" or "",
		  (bit.band(btn, 0x000002) ~= 0) and " Up" or "",
		  (bit.band(btn, 0x000004) ~= 0) and " Rigth" or "",
		  (bit.band(btn, 0x000008) ~= 0) and " Left" or "",
		  (bit.band(btn, 0x000010) ~= 0) and " SR" or "",
		  (bit.band(btn, 0x000020) ~= 0) and " SL" or "",
		  (bit.band(btn, 0x000040) ~= 0) and " L" or "",
		  (bit.band(btn, 0x000080) ~= 0) and " ZL" or "",
		  vibrator(0, 1):uint())
		  pkt.cols.info = "Button" .. str
		  subtree:add(f_subcommandjoy, buf(14,1), buf(14,1):uint(), "BUTTON: " .. str)
	  end

      pkt.src = Address.ip(string.format("%02x.0.0.0", buf(0,1):uint()))
      
  --Host packet
  elseif buf(0,1):uint() == 0xa2
    then
      subtree:add(f_rpt_type, buf(0,1))
      subtree:add(f_command, buf(1,1))
      subtree:add(f_timming, buf(2,1))

      --Check for vibration command only
      if buf(1,1):uint() == 0x10 then 
        pkt.cols.info = "Vibration only set"
        --Calculate real vibration values for left LRA
        local lf_l = buf(5,1):uint()
        local la_l = buf(6,1):uint()
        if lf_l > 127 then
          lf_l = lf_l - 0x80
          la_l = la_l + 0x8000
        end
        local hf_l = buf(3,1):uint()
        local ha_l = buf(4,1):uint()
        local ha_lsb = bit.band(ha_l, -ha_l)
        if ha_lsb == 0x01 then
          hf_l = hf_l + 0x0100
          ha_l = ha_l - 0x01
        end
        --Calculate real vibration values for right LRA
        local lf_r = buf(9,1):uint()
        local la_r = buf(10,1):uint()
        if lf_r > 127 then
          lf_r = lf_r - 0x80
          la_r = la_r + 0x8000
        end
        local hf_r = buf(7,1):uint()
        local ha_r = buf(8,1):uint()
        ha_lsb = bit.band(ha_l, -ha_l)
        if ha_lsb == 0x01 then
          hf_r = hf_r + 0x0100
          ha_r = ha_r - 0x01
        end
        subtree:add(f_rumble, buf(3,8), buf(3,8):uint64(), string.format("Vibration, Left: HF: %04x HA: %02x LF: %02x LA: %04x, Right: HF: %04x HA: %02x LF: %02x LA: %04x", hf_l, ha_l, lf_l, la_l, hf_r, ha_r, lf_r, la_r))
      else
		  subtree:add(f_rumble, buf(3,8), buf(3,8):uint64(), string.format("Vibration, 0x%08x 0x%08x", buf(3,4):uint(), buf(7,4):uint()))
	  end
      

      --Check for MCU command. These are normally used to get states and reports by demand.
      if buf(1,1):uint() == 0x11 then
		  local switch_subcmd = buf(11,1):uint()
        if switch_subcmd == 0x01 then  
          pkt.cols.info = "Get MCU State report?"
          subtree:add(f_subcommand, buf(19,1), buf(19,1):uint(), "MCU subcmd: 0x01 [Get MCU State? or Pairing OUT?]")
        elseif switch_subcmd == 0x03 then
          pkt.cols.info = "Get MCU IR\\NFC Input Report"
          subtree:add(f_subcommand, buf(19,1), buf(19,1):uint(), string.format("Subcmd: 0x03 [Get Input Report], Arg: 0x%02x", buf(20,1):uint()))
        else subtree:add(f_subcommand,buf(19,1))
        end  
      end

      --Check for MCU Firmware Update command.
      if buf(1,1):uint() == 0x03 then
          pkt.cols.info = "Send MCU FW Update packet" 
      end

      --Check if Command is 0x01
      if buf(1,1):uint() == 0x01 then
        --subcommand dissect
		local switch_subcmd = buf(11,1):uint()
        if switch_subcmd == 0x10 then
          pkt.cols.info = "SPI Read"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x10 [SPI Read], Addr: 0x%02x%02x%02x, Size: 0x%02x",
		  buf(14,1):uint(), buf(13,1):uint(), buf(12,1):uint(), buf(16,1):uint()))
        elseif switch_subcmd == 0x01 then
          pkt.cols.info = "Pairing OUT"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), string.format("Subcmd: 0x01 [Pairing OUT], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x02 then
          pkt.cols.info = "Get Device Info"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x02 [Get Device Info]")
        elseif switch_subcmd == 0x11 then
          pkt.cols.info = "SPI Write"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), 
		  string.format("Subcmd: 0x11 [SPI Write], Addr: 0x%02x%02x%02x, Size: 0x%02x",
		  buf(14,1):uint(), buf(13,1):uint(), buf(12,1):uint(), buf(16,1):uint()))
        elseif switch_subcmd == 0x12 then
          pkt.cols.info = "SPI Sector Erase"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x12 [SPI Sector Erase]")
        elseif switch_subcmd == 0x08 then
          pkt.cols.info = "Set Shipment"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), string.format("Subcmd: 0x08 [Set Shipment], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x03 then
          pkt.cols.info = "Set Input Report Format"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), string.format("Subcmd: 0x03 [Set Input Report Format], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x04 then
          pkt.cols.info = "Get L\\R Elapsed Time"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x04 [Get L\\R Elapsed Time]")
        elseif switch_subcmd == 0x05 then
          pkt.cols.info = "Get Page info"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x05 [Get Page Info]")
        elseif switch_subcmd == 0x11 then
          pkt.cols.info = "SPI Write"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x11 [SPI Write], Addr: 0x%02x%02x%02x, Size: 0x%02x",
		  buf(14,1):uint(), buf(13,1):uint(), buf(12,1):uint(), buf(16,1):uint()))
        elseif switch_subcmd == 0x12 then
          pkt.cols.info = "SPI Sector Erase"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x12 [SPI Sector Erase], Arg: 0x%08x %08x",
		  buf(14,4):uint(), buf(18,4):uint()))
        elseif switch_subcmd == 0x00 then
          pkt.cols.info = "Get only Controller State"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x00 [Get only Controller State], Arg: 0x%02x%02x", buf(13,1):uint(), buf(12,1):uint()))
        elseif switch_subcmd == 0x48 then
          pkt.cols.info = "Vibration Enable"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x48 [Vibration Enable], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x40 then
          pkt.cols.info = "6-Axis Enable"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x40 [6-Axis Enable], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x30 then
          pkt.cols.info = "Set Player Lights"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x30 [Set Player Lights], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x06 then
          pkt.cols.info = "Reset Connection"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x06 [!Reset Connection!], Arg: 0x%02x", buf(12,1):uint()))
        elseif switch_subcmd == 0x21 then
          pkt.cols.info = "MCU Config Write"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x21 [MCU Config Write], Arg: %08x %08x %08x %08x %08x %08x %08x %08x %08x %02x",
		  buf(12,4):uint(), buf(16,4):uint(), buf(20,4):uint(), buf(24,4):uint(), buf(28,4):uint(), buf(32,4):uint(), buf(36,4):uint(), buf(40,4):uint(), buf(44,4):uint(), buf(49,1):uint()))
        elseif switch_subcmd == 0x41 then
          pkt.cols.info = "Sensor Write"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x05 [Sensor Write]")
        elseif switch_subcmd == 0x42 then
          pkt.cols.info = "Sensor Config Write"
          subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(),
		  string.format("Subcmd: 0x42 [Sensor Config Write], Arg: %08x %08x %08x %08x %08x %08x %08x %08x %08x %02x",
		  buf(12,4):uint(), buf(16,4):uint(), buf(20,4):uint(), buf(24,4):uint(), buf(28,4):uint(), buf(32,4):uint(), buf(36,4):uint(), buf(40,4):uint(), buf(44,4):uint(), buf(49,1):uint()))
        elseif switch_subcmd == 0x22 then
          if buf(12,1):uint() == 0x00 then
            pkt.cols.info = "MCU Suspend"
            subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x22 00 [MCU Suspend]")
          elseif buf(12,1):uint() == 0x01 then
            pkt.cols.info = "MCU Resume"
            subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x22 01 [MCU Resume]")
          elseif buf(12,1):uint() == 0x02 then
            pkt.cols.info = "MCU Resume for Update"
            subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), "Subcmd: 0x22 02 [MCU Resume for Update]")
          else 
            pkt.cols.info = "MCU Resume set"
            subtree:add(f_subcommand, buf(11,1), buf(11,1):uint(), string.format("Subcmd: 0x22 [MCU Resume set], Arg: 0x%02x", buf(12,1):uint()))
          end
        else subtree:add(f_subcommand,buf(11,1)) end

        subtree:add(buf(12,30), "Subcommand data")
      end

      pkt.dst = Address.ip(string.format("%02x.0.0.0", buf(0,1):uint()))
  end

end

function p_bthid_jc.init()
end

-- register chained dissector for usb packet
usb_table = DissectorTable.get("btl2cap.cid")
-- start after unknown interface class
usb_table:set(0xffff, p_bthid_jc)
