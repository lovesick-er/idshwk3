global agentTable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	local sourceIP: addr = c$id$orig_h;
	if(c$http?$user_agent)
	{
		local agent: string = to_lower(c$http$user_agent);
		if(sourceIP in agentTable)
		{
			add(agentTable[sourceIP])[agent];
		}
		else
		{
			agentTable[sourceIP] = set(agent);
		}
	}
}
event zeek_done()
{
	for(sourceIP in agentTable)
	{
		if(|agentTable[sourceIP]| >= 3)
		{
			print fmt("%s is a proxy", sourceIP);
		}
	}
}
