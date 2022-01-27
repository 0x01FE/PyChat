import os, sys


def fetch_chatroom_data():
	with open("chatrooms/chatroomlist.txt") as f:
		return f.read()
