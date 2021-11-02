require("stream")
require("strutil")
require("dataparser")
require("process")
require("filesys")
require("time")
require("sys")

product_watchlist={}
products_foundlist=""
Version="1.1"

function ItemInWatchlist(item)
local i, pattern

if #product_watchlist == 0 then return true end

for i,pattern in ipairs(product_watchlist)
do
	if string.find(item, pattern) ~= nil
	then
		return true
	end
end

return false
end



function ExtractCVE(str)

if string.sub(str, 1, 1) == "[" then return string.sub(str, 2, strutil.strlen(str) -1) end

return str
end


function RSSAnalyzeString(toks, found_items, found_cve)
local item, str
local watched_items=found_items
local cve=found_cve

item=toks:next()
while item ~= nil
do
	str=string.lower(item)
	if string.sub(str, 1, 4)=="cve-" or string.sub(str, 1, 5) == "[cve-" then cve=ExtractCVE(item) end
	if ItemInWatchlist(str) then watched_items=watched_items .. " "..str end

	item=toks:next()
end

return watched_items, cve
end




function ExamineRSS_CVE(CVE, feed_type)
local toks, tok, item
local cve=""
local info=nil
--matches is things that match our searched product list
local matches="" 
--found_cve is cve numbers associated with matches
local found_cve=""

toks=strutil.TOKENIZER(strutil.htmlUnQuote(CVE:value("title")), "\\S|(|)|,", "m")
matches,found_cve=RSSAnalyzeString(toks, matches, found_cve)


if feed_type=="nvd"
then
	cve=toks:next()
  toks=strutil.TOKENIZER(strutil.htmlUnQuote(CVE:value("description")), "\\S|(|)|,", "m")
	matches,found_cve=RSSAnalyzeString(toks, matches, found_cve)
end


if strutil.strlen(matches) > 0
then
	info={}

	info.feed=feed_type
	if strutil.strlen(found_cve) > 0 then 
	info.cve=found_cve 
	else info.cve=cve
	end
	info.products=matches
	if feed_type == "nvd" 
	then
		info.title=matches
	else
	info.title=strutil.htmlUnQuote(CVE:value("title"))
	end
	info.link=CVE:value("link")

	--full disclosure includes free-form information sometimes including Proof-of-Concept
	--code in the description, so we don't include it
	if feed_type ~= "fulldisclosure" 
	then
		info.description=strutil.htmlUnQuote(CVE:value("description"))
	end
end

return info
end


function RSSGetFeed(url, feed_type, found_items)
local S, doc, P, I, info

print("Querying: '" .. feed_type .. "' feed at '" .. url .. "'")

S=stream.STREAM(url, "r")
doc=S:readdoc()

P=dataparser.PARSER("rss", doc)

I=P:next()
while I ~= nil
do
if string.sub(I:name(), 1, 5) == "item:"
then
	info = ExamineRSS_CVE(I, feed_type)
	if info ~= nil
	then
	table.insert(found_items, info)
	products_foundlist = products_foundlist .. info.products .. ","
	end
end
I=P:next()
end

end


function BuildWatchlist(keywords)
local toks, item

toks=strutil.TOKENIZER(keywords, ",", "Q")
item=toks:next()
while item ~= nil
do
	table.insert(product_watchlist, string.lower(item))
	item=toks:next()
end

end


function FindMailerProgram()
local mailers={"mutt", "mail", "mailx", "sendmail"}
local found, i, prog

for i, prog in ipairs(mailers)
do
	found=filesys.find(prog, process.getenv("PATH"))
	if strutil.strlen(found) > 0 then return found end
end

return ""
end


function PrintUsage()

print()
print("vulnvisor.lua   version:"..Version)
print("   vulnvisor.lua pulls rss feeds from the bugtraq mailing-list, the NIST National Vulnerability Database and the security-focus newsfeed. It displays entries in these feeds that match a list of keywords given on the commandline, and can optionally send output in an email to a single email address. vulnvisor.lua can use the mail, mutt or sendmail programs to dispatch mail.")
print()
print("usage:   vulnadvisor.lua <options> <keyword> <keyword> ...")
print()
print("options:")
print("  -t  <email>          Address to send report to")       
print("  -to <email>          Address to send report to") 
print("  -f  <email>          Sender address for email") 
print("  -from   <email>      Sender address for email") 
print("  -sender <email>      Sender address for email") 
print("  -?                   This help") 
print("  -h                   This help") 
print("  -help                This help") 
print("  --help               This help") 
print()
print("examples:")
print("Print all items in feeds:              'lua vulnvisor.lua'")
print("Print items with keyword 'android':    'lua vulnvisor.lua' android")
print("Mail items with keyword 'android':     'lua vulnvisor.lua' -to me@somewhere.com android")
print("Print items, multiple keywords:        'lua vulnvisor.lua android linux firefox cisco'")
end



function ParseCommandLine(args)
local mailfrom, mailto, i
local watchlist=""

i=1
while i <= #args
do
	if args[i] == "-f" or args[i] == "-from" or args[i] == "-sender"
	then 
		i=i+1
		mailfrom=args[i]
	elseif args[i]== "-t" or args[i] == "-to" or args[i] == "-mailto"
	then 
		i=i+1
		mailto=args[i]
	elseif args[i] == "-?" or args[i] == "-h" or args[i] == "-help" or args[i] == "--help"
	then
		PrintUsage()
		os.exit(0)
	else
		watchlist=watchlist .. "\"" .. args[i] .. "\","
	end

	i=i+1
end

if strutil.strlen(mailfrom) == 0
then
	if process.user ~= nil
	then
		mailfrom=process.user() .. "@" .. sys.hostname()
		if sys.domainname ~= nil then mailfrom = mailfrom .. "." .. sys.domainname() end
	end
end

return mailfrom, mailto, watchlist
end



function SendMail(mailfrom, mailto, products, advise_list)
local mailer, str, S, i, info

mailer=FindMailerProgram()
if strutil.strlen(mailer) > 0
then
	mailer_name=filesys.basename(mailer)
	if mailer_name == "mail" or mailer_name == "mailx"
	then
	str="cmd:".. mailer .. " -a From:" .. mailfrom .. " -s " .. "'Advisories for " .. products .. "' " .. mailto
	elseif mailer_name == "mutt"
	then
	str="cmd:".. mailer .. " -e 'my_hdr From:" .. mailfrom .. "' -s " .. "'Advisories for " .. products .. "' " .. mailto
	elseif mailer_name == "sendmail"
	then
	str="cmd:" .. mailer .. " -f " .. mailfrom .. " ".. mailto
	end
	
	S=stream.STREAM(str)
	if S ~= nil
	then
		if mailer == "sendmail"
		then
			S:writeln(time.format("Date: %a, %d %b %Y %H:%M:%S\n"))
			S:writeln("Subject: Advisories for " .. products .. "\n\n")
		end

		for i, info in ipairs(advise_list)
		do
			S:writeln(info.feed .. ": " .. info.cve .. "  " .. info.title .. "\n")
			if strutil.strlen(info.link) > 0 then S:writeln(info.link .. "\n") end
			if strutil.strlen(info.description) > 0 then S:writeln(info.description .. "\n") end
			S:writeln("\n")
		end
	
		S:close()
	end
else
print("ERROR: No mailer program (sendmail, mail or mutt) found")
end

end

mailfrom,mailto,watchlist=ParseCommandLine(arg)

BuildWatchlist(watchlist)

advise_list={}
RSSGetFeed("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", "nvd", advise_list)
RSSGetFeed("https://seclists.org/rss/fulldisclosure.rss", "fulldisclosure", advise_list)

-- bugtraq seems to be dead
--RSSGetFeed("https://www.securityfocus.com/rss/vulnerabilities.xml", "bugtraq", advise_list)

print()
print(string.format("%d issues found", #advise_list))
print()

for i, info in ipairs(advise_list)
do
	print(info.feed..": "..info.cve.."  "..info.title)
	if strutil.strlen(info.link) > 0 then print(info.link) end
	if strutil.strlen(info.description) > 0 then print(info.description) end
	print()
end

if strutil.strlen(mailto) > 0
then
	SendMail(mailfrom, mailto, products_foundlist, advise_list)
end

