import heapq
import os
from functools import total_ordering
import base64

"""
Code for Huffman Coding, compression and decompression. 
Explanation at http://bhrigu.me/blog/2017/01/17/huffman-coding-python-implementation/
"""
dic=['A','B','C','D','E','F','G','H','I','j','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','-']
@total_ordering
class HeapNode:
	def __init__(self, char, freq):
		self.char = char
		self.freq = freq
		self.left = None
		self.right = None

	# defining comparators less_than and equals
	def __lt__(self, other):
		return self.freq < other.freq

	def __eq__(self, other):
		if(other == None):
			return False
		if(not isinstance(other, HeapNode)):
			return False
		return self.freq == other.freq


class HuffmanCoding:
	def __init__(self, path):
		self.path = path
		self.heap = []
		self.codes = {}
		self.reverse_mapping = {}

	# functions for compression:

	def make_frequency_dict(self, text,split_char,num):
		frequency = {}
		for item in text:
			item=item.rstrip('\n')
			if not item in frequency:
				frequency[item] = 1
			else:
				frequency[item] = frequency[item] + 1
		# return sorted(frequency.items(), key=lambda x: x[1], reverse=True)
 
		# frequency = {}
		# for character in text:
		# 	if not character in frequency:
		# 		frequency[character] = 0
		# 	frequency[character] += 1
		for item,value in frequency.items():
			frequency[item]=value*len(item)
		frequency[split_char]=num
		return frequency

	def make_heap(self, frequency):
		for key in frequency:
			if(key.rstrip()==""):
				continue
			node = HeapNode(key, frequency[key])
			heapq.heappush(self.heap, node)

	def merge_nodes(self):
		while(len(self.heap)>1):
			node1 = heapq.heappop(self.heap)
			node2 = heapq.heappop(self.heap)

			merged = HeapNode(None, node1.freq + node2.freq)
			merged.left = node1
			merged.right = node2

			heapq.heappush(self.heap, merged)


	def make_codes_helper(self, root, current_code):
		if(root == None):
			return

		if(root.char != None):
			self.codes[root.char] = current_code
			self.reverse_mapping[current_code] = root.char
			return

		self.make_codes_helper(root.left, current_code + "0")
		self.make_codes_helper(root.right, current_code + "1")


	def make_codes(self):
		root = heapq.heappop(self.heap)
		current_code = ""
		self.make_codes_helper(root, current_code)


	def get_encoded_text(self, text,frequency):
		encoded_text = text
		for key in frequency:
			encoded_text=encoded_text.replace(key,self.codes[key])

		# for item in text:
		# 	item=item.rstrip('\n')
		# 	encoded_text += self.codes[item]

		return encoded_text


	def pad_encoded_text(self, encoded_text):
		extra_padding = 7 - len(encoded_text) % 7
		for i in range(extra_padding):
			encoded_text += "0"

		padded_info = "{0:07b}".format(extra_padding)
		encoded_text = padded_info + encoded_text
		return encoded_text


	def get_byte_array(self, padded_encoded_text):
		if(len(padded_encoded_text) % 8 != 0):
			print("Encoded text not padded properly")
			exit(0)

		b = bytearray()
		for i in range(0, len(padded_encoded_text), 8):
			byte = padded_encoded_text[i:i+8]
			# print(padded_encoded_text[i:i+8])
			b.append(int(byte, 2))
		return b

	def bitshow(self,text):
		bitList=""
		for item in text:
			item=item.rstrip('\n')
			if(item.rstrip()==""):
				bitList=bitList+"0"
			else:
				bitList=bitList+"1"
		return bitList

	def clearText(self,text):
		clearList=[]
		for item in text:
			item=item.rstrip('\n')
			if(item.rstrip()!=""):
				clearList.append(item)
		return clearList

	def G_place(self,text):
		d="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		G=""
		for c in text:
			index=d.find(c)
			index=index+16
			G=G+d[index]
		return G

	def DEG_place(self,text):
		d="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		G=""
		for c in text:
			index=d.find(c)
			index=index-16
			G=G+d[index]
		return G

	def offset_place(self,text):
		text=text.split("|")
		pattern_offset=""
		d = {}
		index=0
		for item in text:
			info=item.split(":")
			cnt=info[0]
			char=info[1]
			if not char in d:
				d[char] = index
				pattern_offset=pattern_offset+item
			else:
				pattern_offset=pattern_offset+cnt+"_"+str(index-d[char])
				d[char] = index
			index=index+1
		return pattern_offset



	def compress(self):
		filename, file_extension = os.path.splitext(self.path)
		output_path = filename + ".bin"

		with open(self.path, 'r') as file, open(output_path, 'w') as output:
			text = file.readlines()
			# text = text.rstrip('\n')

			bitList=self.bitshow(text)

			ischange=False
			cur_c="0"
			last_c="0"
			index=0
			bitRun=""
			cnt=0
			for c in bitList:
				if index==0:
					cur_c=c
					cnt=1
					index=index+1
				else:
					last_c=cur_c
					cur_c=c
					if(cur_c==last_c):
						cnt=cnt+1
					else:
						bitRun = bitRun + str(cnt)+ ":" + last_c
						# bitRun=bitRun+str(hex(cnt)).replace("0x","")+":"+last_c
						cnt=1
					index=index+1
			bitRun = bitRun + str(cnt) + ":" + cur_c
			# bitRun=bitRun+str(hex(cnt)).replace("0x","")+":"+cur_c
				
			clear_text=self.clearText(text)
			text=clear_text
			# output.write(bitRun)


			index=0
			cnt=0
			cur_c=""
			last_c=""
			pattern=""
			for c in text:
				if index==0:
					cur_c=c
					cnt=1
					index=index+1
				else:
					last_c=cur_c
					cur_c=c
					if(cur_c==last_c):
						cnt=cnt+1
					else:
						pattern = pattern + str(cnt) + ":" + last_c
						# pattern=pattern+str(hex(cnt)).replace("0x","")+":"+self.G_place(last_c)+"|"
						cnt=1
					index=index+1
			pattern = pattern + str(cnt)+ ":" + cur_c
			# pattern=pattern+str(hex(cnt)).replace("0x","")+":"+self.G_place(cur_c)

			# pattern=self.offset_place(pattern)

			output.write(bitRun+pattern)
			#
			# # # output.write(pattern)
			# cur_text=bitRun+pattern
			# num=cur_text.count(':')
			# text=cur_text.strip(':')
			#
			# # output.write('\n')
			# frequency = self.make_frequency_dict(text,':',num)
			# self.make_heap(frequency)
			# self.merge_nodes()
			# self.make_codes()
			#
			# encoded_text = self.get_encoded_text(cur_text,frequency)
			# # encoded_text=bitList+encoded_text
			# padded_encoded_text = self.pad_encoded_text(encoded_text)
			#
			# # b = self.get_byte_array(padded_encoded_text)
			# # output.write(bytes(b))
			#
			# # b = self.get_byte_array(padded_encoded_text)
			# # print (b)
			# # output.write(base64.b64encode(bytes(b)))
			#
			# tb=""
			# # output.write(bitRun)
			# for i in range(0, len(padded_encoded_text), 7):
			# 	b64 = padded_encoded_text[i:i+7]
			# 	# print(padded_encoded_text[i:i+8])
			# 	# print(int(b64, 2))
			# 	# output.write(chr(int(b64, 2)))
			# 	tb+=(chr(int(b64, 2)))
			# output.write(tb)
			

		print("Compressed")
		return output_path

















	""" functions for decompression: """


	def remove_padding(self, padded_encoded_text):
		padded_info = padded_encoded_text[:8]
		extra_padding = int(padded_info, 2)

		padded_encoded_text = padded_encoded_text[8:] 
		encoded_text = padded_encoded_text[:-1*extra_padding]

		return encoded_text

	def decode_text(self, encoded_text):
		current_code = ""
		decoded_text = ""

		for bit in encoded_text:
			current_code += bit
			if(current_code in self.reverse_mapping):
				character = self.reverse_mapping[current_code]
				decoded_text += character
				current_code = ""

		return decoded_text


	def decompress(self, input_path):
		filename, file_extension = os.path.splitext(self.path)
		output_path = filename + "_decompressed" + ".txt"

		with open(input_path, 'rb') as file, open(output_path, 'w') as output:
			bit_string = ""

			byte = file.read(1)
			while(len(byte) > 0):
				byte = ord(byte)
				bits = bin(byte)[2:].rjust(8, '0')
				bit_string += bits
				byte = file.read(1)

			encoded_text = self.remove_padding(bit_string)

			decompressed_text = self.decode_text(encoded_text)
			
			output.write(decompressed_text)

		print("Decompressed")
		return output_path


if __name__ == "__main__":  # pragma: no cover
	# path = ["_X86_legacy","_X86_prefix","_X86_opcode","_X86_modrm","_X86_sib","_X86_rest"]
	path=["_X86_legacy","_X86_prefix","_X86_modrm","_X86_sib"]
	for pi in path:
		h = HuffmanCoding(pi)
		output_path = h.compress()
		print("Compressed file path: " + output_path)

	#decom_path = h.decompress(output_path)
	#print("Decompressed file path: " + decom_path)
