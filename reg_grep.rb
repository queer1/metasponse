##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

        include Msf::Post::Common
        include Msf::Post::Windows::Registry


        def initialize(info={})
                super( update_info( info,
                                'Name'          => 'Registry Grep',
                                'Description'   => %q{ This module searchings for registry keys},
                                'License'       => MSF_LICENSE,
                                'Author'        => [ 'MJC'],
                                'Version'       => '$Revision$',
                                'Platform'      => [ 'windows' ],
                                'SessionTypes'  => [ 'meterpreter' ]
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
                        output = registry_enumkeys(key)
                        if output
                                print_good("#{sysinfo['Computer']}: #{key} found in registry.")
                                match += 1
                        end
                end
                print_status("#{sysinfo['Computer']}: #{match} result(s) found in registry.")
        end
end