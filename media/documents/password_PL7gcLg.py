from random import *
import os
upwd = input("Enter your Password : ")
pwd = ['1','2','3','4','5','6','7','8','9','0','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z']
li = []
pw=""
count= 0
try:
	while(pw!=upwd):
		pw=""
		for i in range(len(upwd)):
			gpwd = pwd[randint(0,35)]
			pw = str(gpwd)+str(pw)
			count = count + 1
		li.append(pw)
		print("Cracking Password")
except:
	print(li)
	print(count)
print(li)
print(count)