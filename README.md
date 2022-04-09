# PwAnalyzer
Password Strength Analyzer


Criteria:
1. Have both upper lower case
2. Contains at least one number
3. Contains at least one symbol / special character
4. Have a minimum of 8 character

the score increases by 1 every time the criteria are met
if length < 5, score is reduced by 1
if length > 12, score is added by 2

if final score is 5, the strength is excellent,
if final score is 4, the strength is strong,
if final score is 3, the strength is medium,
if final score is 2, the strength is weak,
otherwise the strength is worst