##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Post::Windows::Registry


	def initialize(info={})
		super( update_info( info,
							'Name' => 'Registry Grep',
							'Description' => %q{ This module searchings for registry keys},
							'License' => MSF_LICENSE,
							'Author' => [ 'MJC'],
							'Version' => '$Revision$',
							'Platform' => [ 'windows' ],
							'SessionTypes' => [ 'meterpreter' ]
				))
				register_options(
				[
					OptString.new('KEYS',[true,'Registry value, separate multiple by comma.'])
				], self.class)

	end

	# Run Method for when run command is issued
	def run
		match = 0
		print_status("Searching registry on #{sysinfo['Computer']}")
		keys = datastore['KEYS'].split(/,/)
		keys.each do |key|
			(key, value) = parse_query(key)
			print_status("#{sysinfo['Computer']}: Search for => #{key}\\#{value}")
			has_key = registry_enumkeys(key)
			has_val = registry_enumvals(key)

			if not has_key.grep(value).empty? or not has_val.grep(value).empty?
				print_good("#{sysinfo['Computer']}: #{key}\\#{value} found in registry.")
				match += 1
			end
		end
		print_status("#{sysinfo['Computer']}: #{match} result(s) found in registry.")
	end
	
	#This method parses the key path which provides searchable strings
	def parse_query(key)
		path = key.split("\\")
		value = path[-1]
		path.pop
		key = path.join("\\")
		return key, value
	end
end
