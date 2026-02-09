import sys

print(sys.argv)
input_stdin = sys.stdin.read()
print(f"z stdin: {input_stdin}, argv: {sys.argv}")
# https://stackoverflow.com/questions/31904875/precedence-of-shell-operator
# https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html#tag_18_10_02
# https://tldp.org/LDP/abs/html/opprecedence.html
# https://stackoverflow.com/questions/20536112/how-can-i-insert-a-new-line-in-a-linux-shell-script
# https://stackoverflow.com/questions/7640360/how-to-redirect-back-to-stdout-after-using-dup2-and-using-execvp
# https://stackoverflow.com/questions/749049/passing-a-multi-line-string-as-an-argument-to-a-script-in-windows
# \xa0
# https://stackoverflow.com/questions/29067335/when-piping-why-do-you-have-to-close-the-opposite-end-of-a-pipe-before-using
# https://stackoverflow.com/questions/21914632/implementing-pipe-in-ck
# https://stackoverflow.com/questions/3385201/confused-about-stdin-stdout-and-stderr