#!/usr/bin/env python3
#encoding: utf-8

import os
from dns import resolver

from requests import get
from cortexutils.analyzer import Analyzer
from DNS_records import RECORDS, CODE
from json import loads, dumps
from traceback import format_exc

class NSLookup_resolve(Analyzer):

	def __init__(self):

		Analyzer.__init__(self)
		self.url = "https://dns.google.com/resolve?"
		self.proxies = None
		self.answer = None

		"""
		print("\ninit: ###############")
		print( dumps(self.__dict__, indent=4, sort_keys=True) )
		print("init: ###############")
		"""

	def resolveGoogleDNS(self, query):
		# print("\nresolveGoogleDNS: ###############")

		query = {
			"name" : query,
			"type" : "ANY"
		}

		try:
			data = loads( get(self.url, params=query, proxies=self.proxies).text ) 
		except Exception as e:
			self.report(format_exc())
		else:
			# print( dumps(data, indent=4, sort_keys=True) )

			if data['Status'] == 0: # DNS response code
				if 'Answer' in data: # Maybe nothing is found

					for records in data['Answer']: # for each records found by Google
						try:
							records["type"] = RECORDS[records["type"]]  # replace IANA code by record name
						except KeyError:
							data["Error"] = "Invalid IANA code : {0}".format(int(records["type"]))	# Maybe using a special code
				else:
					data['Answer'] = [] 
				
			else: # If the DNS response match an error code
				try:
					# known DNS error code
					data["Error"] = "Error for {0} : {1}".format(data['Question'][0]['name'], CODE[int(data["Status"])])
				except KeyError:
					# DNS error code is unknow
					data["Error"] = "Unknow error : {0}".format(int(data["Status"]))
				
			self.answer = data
			self.answer['Question'][0]['type'] = RECORDS[data['Question'][0]['type']] # eplace IANA code by record name 
			self.answer["Status"] = CODE[int(data["Status"])] # replace DNS response code by name

		#print("resolveGoogleDNS: ###############\n")

	def resolveNsLookup(self, query):
		"""
		print("\nresolveNsLookup: ###############")
		print("resolveNsLookup: query: %s " % query)
		"""

		result = os.popen('nslookup -type=any ' + query).read()

		"""
		print("resolveNsLookup: result:\n%s" % result)
		print("resolveNsLookup: ###############\n")
		"""

	def resolveDnsPython(self, query):
		#print("\nresolveDnsPython: ###############")

		self.answer = {}
		self.answer['Answer'] = {}
		self.answer['Question'] = query

		errors = {}

		try:
			result = resolver.query( query, 'NS')
		except Exception as e:
			errors["NS"] = e.msg
		else:
			i = 1
			for ipval in result:
				self.answer["Answer"]["NS"+str(i)] = ipval.to_text()[:-1]
				i += 1

		try:
			result = resolver.query( query, 'SOA')
		except Exception as e:
			errors["SOA"] = e.msg
		else:
			for ipval in result:
				self.answer["Answer"]["SOA"] = ipval.to_text()

		try:
			result = resolver.query( query, 'MX')
		except Exception as e:
			errors["MX"] = e.msg
		else:
			i = 1
			for ipval in result:
				self.answer["Answer"]["MX"+str(i)] = ipval.to_text()[:-1]
				i += 1

		try:
			result = resolver.query( query, 'A')
		except Exception as e:
			errors["A"] = e.msg
		else:
			i = 1
			for ipval in result:
				self.answer["Answer"]["A"+str(i)] = ipval.to_text()
				i += 1

		try:
			result = resolver.query( query, 'AAAA')
		except Exception as e:
			errors["AAAA"] = e.msg
		else:
			i = 1
			for ipval in result:
				self.answer["Answer"]["AAAA"+str(i)] = ipval.to_text()
				i += 1

		self.answer["Errors"] = errors
		self.answer["Status"] = "Alright."

		#print("resolveDnsPython: ###############\n")

	def run(self):
		#print("\nrun: ###############")

		if self.data_type not in ["ip", "domain", "fqdn"]:
			self.error("Wrong data type")

		target = self.getData()

		self.proxies = {
			"https" : self.getParam("config.proxy_https"),
			"http" : self.getParam("config.proxy_http")
		}

		target = ".".join(target.split('.')[::-1]) + '.in-addr.arpa' if self.data_type == "ip" else target

		# Resolve via Google HTTP API:
		#self.resolveGoogleDNS( target )

		# Resolve via local NSLookup:
		#self.resolveNsLookup( target )

		# Resolve via local NSLookup:
		self.resolveDnsPython( target )

		"""
		print( "NSLookup_resolve::run: content of self:" )
		print( dumps(self.__dict__, indent=4, sort_keys=True) )
		"""

		if self.answer != None:
			self.report(self.answer)
		else:
			self.error("Something went wrong")

	def summary(self, raw):
		count = self.build_taxonomy("info", "NSLookup", "RecordsCount", len(self.answer["Answer"]))
		return { "taxonomies" : [count]}

if __name__ == "__main__":
	NSLookup_resolve().run()
