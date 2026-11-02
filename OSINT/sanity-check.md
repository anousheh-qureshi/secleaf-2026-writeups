# Category: OSINT / Reconnaissance (1 PTS)
## Objective: Track down the disguised SecLeaf presence on Instagram and recover the flag hidden inside the restricted comments of a historical post.

# Solution:
The CTF portal provided the following clue within the challenge modal:
You know you want me, you know you need me, Find me where I am a disguise of SecLeaf on Instagram.
Flag format: SecLeaf{}
## Write-up
The prompt explicitly labeled the official corporate links (@secleafofficial) as 'Unrelated/Related Slop', confirming that the true target was a secondary or dormant account disguise.
Investigating Historical Instagram Handles
Searching Instagram directly for 'secleaf' uncovered a dormant account registered as @secleaf with historical activity dating back to 2016. A photo of pink cherry blossoms posted on December 9, 2016 contained active comment activity from other CTF participants asking for the flag.
Uncovering Hidden / Restricted Comments
Instagram automatically collapsed filtered comments under 'Hidden by Instagram'. Expanding this restricted comments view revealed the authentic flag submitted by user satisfyingblends:
satisfyingblends: SecLeaf{w3_w4nt_th1s_4cc0unt}


## Identified Decoys
Location / Attempt	Decoy Flag / Value	Why it is a Decoy / Result
Official Instagram (@secleafofficial)	Company Profile Page	Explicitly marked 'Slop'; standard social media
CTF Portal Submission	SecLeaf{broken_anna}	Tested hypothesis; returned 'Incorrect'
Visible Comments	casualanimevibes, foxfm1987	Participant noise and chatter
Restricted Comments View	SecLeaf{w3_w4nt_th1s_4cc0unt}	Accepted valid flag hidden behind Instagram filter


<b>FLAG: SecLeaf{w3_w4nt_th1s_4cc0unt}</b>

Flag was found by <i>anousheh_qureshi</i>
