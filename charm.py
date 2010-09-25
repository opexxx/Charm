#!/usr/bin/env python

__author__ = 'Grant Stavely'
__version__ = '0.0.1'
__date__ = '2010/01/11'

"""
Use at your own risk

History:
  2010/01/11: start

"""

import warnings
import optparse
import os
import re
import traceback 
import math
import operator
import errno
import sys
import subprocess 
import magic
import smtplib
import hashlib
import shutil
import email
import mimetypes
import string
import zipfile
import tempfile
import glob
import pefile
import peutils
import datetime
from chm.chm import CHMFile
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email import Encoders
from email import FeedParser
from pipes import quote
import time
import syslog
import tarfile

"""
Scanning Classes
"""

class Scan:
    """Scann files for basic attributes

    Args: 
        file: fully qualified file path name
        mimetype: optional argument if you think you know better than magic hints

    Returns: 
        A 'scan' object reference, used in subsequent method calls for 
        further file scanning with more specific scanners
    """
    def __init__(self, file, mimetype=False):
        self.findings = []
        self.score = 0
        self.file = os.path.abspath(file)
        self.name = os.path.basename(self.file)
        self.size = os.path.getsize(self.file)
        self.interesting = False
        self.hits = []
        if mimetype:
            self.mimetype = mimetype
        else:
            """grab the MIME type from magic hints"""
            magic_hint = magic.open(magic.MAGIC_NONE)
            magic_hint.load()
            self.mimetype = magic_hint.file(file)
        try:
            """hash the file and keep the payload for later"""
            self.payload = open(self.file, 'rb').read()
        except Exception, error:
            log("Unable to open and read %s. Error: %s" % (self.file, error))
        self.md5 = hashlib.md5(self.payload)
        self.sha1 = hashlib.sha1(self.payload)
        # and calculate file entropy - 
        # found at http://hooked-on-mnemonics.blogspot.com/p/portable-executable-virustotal-example.html
        # who got it from http://blog.dkbza.org/
        self.entropy = 0
        ent = 0
        if self.payload:
            for x in range(256):
                p_x = float(self.payload.count(chr(x)))/len(self.payload)
                if p_x > 0:
                    self.entropy += p_x*math.log(p_x, 2)
        # and wrap our basic findings into something of a Report
        self.findings.append("""File: %s, %d bytes, Entropy: %d
(%s, %s)
http://www.threatexpert.com/Report.aspx?md5=%s
http://fileadvisor.bit9.com/services/extinfo.aspx?md5=%s
http://anubis.iseclab.org/?action=home
http://www.virustotal.com/buscaHash.html

""" % (self.name, self.size, self.entropy, self.md5.hexdigest(), self.md5.hexdigest(), self.sha1.hexdigest(), self.md5.hexdigest()))
        log("Examining: %s, Mimetype: %s, md5: %s, Size: %d, Entropy: %d" % (self.name, self.mimetype, self.md5.hexdigest(), self.size, self.entropy))
        if self.payload:
            # Eicar test string (encoded for skipping virus Scanners)
            EICAR = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E'.decode('base64') \
                            +'QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n'.decode('base64')
            if EICAR in self.payload:
                self.findings.append("EICAR-STANDARD-ANTIVIRUS-TEST-FILE!")
                self.interesting = True

    def hash_match(self):
        icscert = ['bdbdd1ea58bccc69ad233e737be1a68b', 'bdbdd1ea58bccc69ad233e737be1a68b', 'c04327d496f5840598b5bd89fd591b5b', '1dcd4a3f5d05433fcebf88d9138a1966', 'C6F03329B92C040A0BF670429E61DAD0', '4B873EFF177AE6E03C0CDE798CFC796C', '7413A7C86B54689C5829E313556F7BE8', '1BBCB6B4530F4732732158E954939E74', '33EA9FD0DAD6C37B6DD56806CDD59224', '109BBCC8A8E2EF7C7AD828D16D9FDFA9', '0696697473502F001C9A8055610342D1', '6FB7BAAF8E14F8F6A9994BAC0BBD6F4B', 'D401FFC81D2DD6B6EF609D45C30BC4CE', 'D3078F602AA4A9E7A8B81F61D00CD046', '8F44B4E4EBF9CB732FD5B53750170651', '6901EC598137B21A55728ED0FAF0551F', '292F9794E2A8212666DF609E64CFA0FF', '427B810AE52F5CC28D53A956C8E0DC0E', 'E851D917CDAF4E592312014C8A0C4C92', '48437EB28FF1BFFF5C0A4661A8C3055D', 'C100BDE0C1E0D7E77DCBC6E00BC165F3', '30D50F856EFE9BCF7D0A859154CB2F92', 'B2AED7875F1F403D4126355481DEDDDB', 'E5C8569910ED9F808D8159A7E9414DD9', '23B6D8D9BCEFCD84ED96150E924E31D8', '0670338B794D58D11A0E2AB6CD0B2FA4', 'F71D7C946B9FE8EFA9188E33CF574210', 'C5BEA02646DA02ECB31A0F80F9814B7B', '310CBA19E6F7FD07ADF203C27E46A0C9', '9CB4EE95948292BE131F7C4EE3BDCF21', 'BAE0E04D876BA34283BC3F207F7E51BB', '869C153070378221FBDA2E197EB92AEB', 'F287EA24D022164942A9B794F3612C35', 'E2BFD89DCF7EB72A89CC47C7B7DFB703', '93122132B8C96A0B035547C1C13574E5', '0AF91920AF5CFC4BDCAF67D11BF4F09B', 'D46D261EC92DAF703CD584F10037198C', 'DAE7B296186E1D093FE3CFD3384674D9', 'E2BCDFA1D66ED53FA017395DA615A55F', '1CEB117C10F9C799C3876E1C40B8E9C5']
        for cert in icscert:
            if self.md5.hexdigest() == cert.lower():
                self.interesting = True
                log("Identified known evil hash: %s" % self.md5.hexdigest())
                self.findings.append("Known malicious file hash: %s\n" % self.md5.hexdigest())

    def pdfid(self):
        self.interesting_score = 3
        self.has_output = True
        # jump out to execute the Scanner
        log("Waiting for pdfid.py to Scan %s" % self.file)
        Scanner = ["/usr/local/bin/python", "/nsm/bin/pdfid.py", "-se", self.file]
        try:
            Scan = subprocess.Popen(Scanner, shell=False, stdout=subprocess.PIPE)
        except Exception, error:
            log("    Unable to Scan %s with pdfid. Error: %s" % (file, error))
        self.output, errors = Scan.communicate()
        if errors:
            log("   Error: %s" % errors)
        # specific pdfid attributes
        entropy = 0
        baseEntropy = 6
        suspiciousTZs = '+08', '+03', '+03\'30'
        # Parse parse bork bork
        pdfid = {'Noteworty' : False}
        pdfid ['Javascript'] = re.search(r"JavaScript\s+([1-9]+)+", self.output)
        pdfid ['JS'] = re.search(r"/JS\s+([1-9]+)+", self.output)
        pdfid ['OpenAction'] = re.search(r"/OpenAction\s+([1-9]+)+", self.output)
        pdfid ['JBIG2Decode'] = re.search(r"/JBIG2Decode\s+([1-9]+)+", self.output)
        pdfid ['AA'] = re.search(r"/AA\s+([1-9]+)+", self.output)
        pdfid ['Launch'] = re.search(r"/Launch\s+([1-9]+)+", self.output)
        one_page = re.search(r"\s\/Page\s+(1)\D", self.output)
        tz_offset = re.search(r"\sD:\d+([+-]\d{1,2}.\d{1,2})", self.output)
        entropy = re.search(r"[eE]ntropy.+\s+(\d+\.\d+)", self.output)
        # throw hits into a list to print later
        for finding, present in pdfid.iteritems():
            if present:
                self.score += 1
                self.hits.append("%s: %s" % (finding, present.group(1)))
        if entropy:
            if (float(entropy.group(1)) < baseEntropy):
                self.hits.append("Entropy less than %d: %d" % (baseEntropy, float(entropy.group(1))))
                self.score += 1
        if one_page:
            self.hits.append("Pages: 1")
            self.score += 1
        if tz_offset:
            for tz in suspiciousTZs:
                if tz_offset.group(1).startswith(tz):
                    self.hits.append("Suspicious timestamp: %s" % (tz_offset.group(1)))
        if self.score > self.interesting_score:
            self.interesting = True
        # pull the stats regardless
        self.findings.insert(1, "Score: %d, %s" % (self.score, ", ".join(self.hits)))
        self.findings.append(self.output)

    def chm(self):
        # all chm files suck
        self.interesting = True
        chmfile = CHMFile()
        chmfile.LoadCHM(self.file)
        self.findings.append("CHM file locale: %s" % ", ".join(chmfile.GetLCID()))
        chmfile.CloseCHM()

    def pescan(self):
        pe = pefile.PE(self.file)
        hits = []
        machine = 0
        machine = pe.FILE_HEADER.Machine
        # massive dumps of pefile data
        # userdb lookup time
        signatures = peutils.SignatureDatabase('/nsm/bin/userdb.txt')
        matches = signatures.match_all(pe,ep_only = True)
        self.findings.append("PEID Signature Match(es): %s" % matches)
        self.findings.append("Optional Header: %s\n" % hex(pe.OPTIONAL_HEADER.ImageBase))
        self.findings.append("Address of Entry Point: %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
        self.findings.append("Required CPU type: %s\n" % pefile.MACHINE_TYPE[machine])
        self.findings.append("DLL: %s\n" % pe.FILE_HEADER.IMAGE_FILE_DLL)
        self.findings.append("Subsystem: %s\n" % pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem])
        self.findings.append("Compile Time: %s\n" % datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp))
        self.findings.append("Number of RVA and Sizes: %s\n" % pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
        self.findings.append("Number of Sections: %s\n" % pe.FILE_HEADER.NumberOfSections)
        self.findings.append("Section  VirtualAddress VirtualSize SizeofRawData\n")
        self.findings.append(pe.dump_info())

        for section in pe.sections:   
            self.findings.append("%-8s%-14s%-11s%-13s\n" % (section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize),\
            section.SizeOfRawData))
        # everything interesting is executable, therefore all executables are interesting
        self.interesting = True
        log("Identified executable: %s, %s" % (self.name, self.mimetype))


"""
File handling / unbundling classes
"""
class Bundle:
    def __init__(self, file):
        self.files = []
        self.file = file.file
        self.summary = []
        self.contents = []
        self.bundle_name = ''

class Unzip(Bundle):
    def walk(self):
        self.summary.append("Extracting contents of %s" % self.file)
        verbose("Extracting contents of %s" % self.file)
        zip = zipfile.ZipFile(self.file)
        for subfile in zip.namelist():
            verbose("Found %s in %s" % (subfile, self.file))
            self.summary.append("\t%s" % (subfile))
            payload = zip.read(subfile)
            temp_files = temp(subfile, payload)
            self.contents.append(temp_files)
            extracted_files = Scan(temp_files.file.name)
            self.files.append(extracted_files)
        return self.files

class Untar(Bundle):
    """
    The tarfile module doesn't protect us from dumping files on /
    so we'll pull the payload and create our own temp files, ignoring
    the directory structure entirely 
    """
    def walk(self):
        verbose("Extracting contents of %s" % self.file)
        tar = tarfile.open(self.file)
        self.summary.append("Contents of %s" % self.file)
        for file in tar.getnames():
            extracted_file = tar.extractfile(file)
            payload = extracted_file.read()
            extracted_file = temp(file, payload)
            self.contents.append(extracted_file)
            scanned = Scan(extracted_file.file.name)
            self.files.append(scanned)
            # return Scan instances, not filenames
        print self.summary
        return self.files
 
class Demime(Bundle):
    """Subclass of Bundle, returns extracted Scan objects."""
    def walk(self):
        try:
            mimefile = open(self.file)
        except Exception, error:
            log("Demime: Unexpected error reading %s to Demime. Error: %s" % (self.file, error))
        """Grab the first 1000 bytes from the wraper to grab exim's headers"""
        exim_headers = mimefile.read(10000)
        if re.match(r"From", exim_headers):
            sender = re.search(r"From (\S*) ", exim_headers).group(1)
            recipient = re.search(r"for (\S*);", exim_headers).group(1)
            subject = re.search(r"Subject: (.*)", exim_headers).group(1)
            self.summary.append("Sender: %s\n" % sender)
            self.summary.append("Recipient: %s\n" % recipient)
            self.summary.append("Subject: %s\n" % subject)
            verbose("Demime: Mime message identified, sender: %s, recipient: %s, subject: %s" % (sender, recipient, subject))
            mimefile.seek(0)
            self.msg = email.message_from_file(mimefile)
        self.counter = 1
        for part in self.msg.walk():
            mimetype = part.get_content_type()
            extension = mimetypes.guess_extension(part.get_content_type())
            if extension == ".ksh":
                extension = ".txt"
            payload = part.get_payload(decode=True)
            filename = part.get_filename()
            verbose("Demime: Layer %d mimetype: %s" % (self.counter, mimetype))
            self.counter += 1
            if payload:
                if not filename:
                    verbose("Demime: %s file, but unable to determine file name." % mimetype)
                    # fuzzy onion layers - if you have a predictable SMTP source forwarding messages, 
                    # replace YOUR MESSAGE HERE with a known string in the source to identify it as such.
                    # Do the same for the X-Forwarded header
                    if re.match(r"YOUR MESSAGE HERE", payload):
                        sender = re.search(r">From (\S*) ", payload)
                        if sender:
                            sender = sender.group(1)
                        else:
                            sender = ""
                        recipient = re.search(r"X-Forwarded: (\S*)", payload)
                        if recipient:
                            recipient = recipient.group(1)
                        else:
                            recipient = ""
                        subject = re.search(r"Subject: (.*)", payload)
                        if subject:
                            subject = subject.group(1)
                        else:
                            subject = ""
                        self.summary.append("Sub-message Sender: %s\n" % sender)
                        self.summary.append("Sub-message Recipient: %s\n" % recipient)
                        self.summary.append("Sub-message Subject: %s\n" % subject)
                        self.bundle_name = ("%s-%s-%s" % (sender, recipient, subject))
                        log("Demime: sender: %s, recipient: %s, subject: %s" % (sender, recipient, subject))
                        filename = "Ironport.txt"
                    # also specifically match on known common text types and given them default names
                    elif re.match(r"<[!]\w+", payload, re.IGNORECASE) or extension == ".html":
                        extesion = '.txt'
                        filename = "HTMLEmail%s" % extension
                    else:
                        filename = "OriginalEmail%s" % extension
                Demimed = temp(filename, payload, self.counter)
                self.contents.append(Demimed)
                scanned = Scan(Demimed.file.name, mimetype)
                self.files.append(scanned)
                # return Scan instances, not filenames
        return self.files


"""
Reporting classes
"""

class Report:
    def __init__(self):
        """Parent class for all reporting output"""
        self.text = []
        self.interesting = False
        self.attachments = []
        self.msg = MIMEMultipart()
        self.msg['From'] = options.recipient
        self.msg['To'] = options.recipient

class ConsoleReport(Report):
    """Subclass of Report, prepares charm for standard console output"""
    def attach_file(self, filename, payload, mimetype):
        print os.path.basename(filename)

    def send(self, subject=False):
        print "\n".join(self.text)

    def attach_text(self):
        pass

class EmailReport(Report):
    """Subclass of Report, prepares charm for email reporting with MIME attachments.
       only text attachments types are permitted"""
    def attach_file(self, filename, payload, mimetype):
        if re.search('text', mimetype, re.IGNORECASE):
            if re.search('/', mimetype):
                (maintype, subtype) = mimetype.split('/')
                attachment = MIMEBase(maintype, subtype)
            else:
                attachment = MIMEBase('text', 'plain')
            attachment.set_payload(payload)
            Encoders.encode_base64(attachment)
            attachment.add_header('Content-Disposition', 'attachment', filename=filename)
            self.msg.attach(attachment)
        else:
            log("Cowardly refusing to attach %s, %s as it is potentially malicious" % (filename, mimetype))
            pass

    def attach_text(self):
        self.msg.attach(MIMEText("\n".join(self.text)))

    def send(self, subject='Suspicous inbound email'):
        self.msg['Subject'] = subject
        log("Sending Report to " + options.recipient)
        smtp = smtplib.SMTP(options.mta)
        smtp.sendmail(options.recipient, options.recipient, self.msg.as_string())
        smtp.close()

"""
File Storage classes
"""
class temp:
    def __init__(self, filename, payload=0, counter=0, extension=False):
        self.basename = filename
        self.name = os.path.realpath(filename)
        self.payload = payload
        if not extension:
            (self.basename, self.extension) = os.path.splitext(self.basename)
            # annoyingly there is still a . in the extension
        else:
            self.extension = ".%s" % extension
        self.counter = counter
        self.filename = "%s-%03d-CEG-" % (self.basename, self.counter)
        # save the initial temp file to disk by default
        try:
            self.file = tempfile.NamedTemporaryFile(mode='w+b', suffix=self.extension, prefix="%s" % self.filename, delete=False)
            verbose("Creating a temp file for: %s%s: %s" % (self.basename, self.extension, self.file.name))
        except Exception, error:
            log("Unable to create temp file: %s. Error: %s" % (self.filename, error))
        try:
            self.file.write(payload)
        except Exception, error:
            log("Unable to write to %s. error: %s" % (self.filename, error))
        self.file.close()

    def destroy(self):
        try:
            verbose("Removing temp file: %s" % self.file.name)
            os.remove(self.file.name)
        except Exception, error:
            log("Unable to clean up temporary file: %s Error: %s" % (self.file.name, errorname))


class archive:
    def __init__(self, sender='local', recipient='local', subject='Scan'):
        # set up local storage immediately
        now = time.localtime()
        year = now.tm_year
        month = now.tm_mon
        day = now.tm_mday
        hour = now.tm_hour
        minutes = now.tm_min
        seconds = now.tm_sec
        path = quote("/nsm/var/malware/%d/%02d/%02d" % (year, month, day))
        stamp = "%d.%02d.%02d.%02d.%02d.%02d" % (year, month, day, hour, minutes, seconds)
        if not os.access(path, os.W_OK):
            try:
                os.makedirs(path, 0750)
            except Exception, error:
                log("Unable to create archive directory %s, Error: %s" % (path, error))
        self.archive_name = "%s/%s-to-%s--%s.%s.tar.gz" % (path, sanitize_filename(sender), sanitize_filename(recipient), sanitize_filename(subject), stamp)

    def add_file(self, file):
        log("Logging %s to %s" % (file, self.archive_name))
        try:
            self.tarball = tarfile.open(self.archive_name, "w:gz")
        except Exception, error:
            log("Unable to open %s. Error: %s" % (self.archive_name, error))
        # chdir to the basepath so that the tar file isn't full of /var/spool/exim/etc...
        os.chdir(os.path.dirname(file))
        file = os.path.basename(file)
        try:
            self.tarball.add(file)
        except Exception, error:
            log("Unable to add %s to %s. Error: %s" % (file.name, self.archive_name, error))
        self.tarball.close()

"""
Workhorse class
"""

class Charm:
    def __init__(self, args):
        # Report once per run
        if options.recipient:
            self.Report = EmailReport()
        else:
            self.Report = ConsoleReport()
        # shell glob the actual file paths and store their stats
        self.given_files = []
        self.Scan_files = []
        self.scanned_files = []
        self.scan_name = 'Charm'
        verbose("arg provided: %s" % args)
        # and then make sure it is a file
        for entry in args:
            for file in glob.glob(entry):
                verbose("entry to review %s" % file)
                if os.path.isdir(file):
                    log("Error: Cowardly refusing to Scan ambiguous directory entry: %s, try using shell wildcards" % file)
                    continue
                self.given_files.append(Scan(file))
        # keep a list of temp files object references to clean up later
        self.temp_files = []
        # unBundle groups of files, ditch known files
        for file in self.given_files:
            Bundle = False
            self.scanned_files.append(file)
            if re.search('mail', file.mimetype, re.IGNORECASE):
                Bundle = Demime(file)
                """Attach any found email as text documents"""
                original = temp('EmailGivenToCharm', file.payload, 0, 'txt')
                self.Report.attachments.append(Scan(original.file.name))
                self.temp_files.append(original)
            if re.search('zip archive', file.mimetype, re.IGNORECASE):
                Bundle = Unzip(file)
            if re.search('tar archive', file.mimetype, re.IGNORECASE):
                Bundle = Untar(file)
            # don't Scan ourselves - this is naive and probably should be done better
            if re.search('_scanner_output$', file.name, re.IGNORECASE):
                continue 
            if Bundle:
                for file in Bundle.walk():
                    self.given_files.append(file)
                    if file.mimetype.find('text'):
                        # and we can pluck off the plain text temp files to attach to the Report
                        self.Report.attachments.append(file)
                # and now that we've walked the Bundle, add the summary to the master Report
                for file in Bundle.contents:
                    self.temp_files.append(file)
                if Bundle.summary:
                    self.Report.text.append("".join(Bundle.summary))
                if Bundle.bundle_name:
                    self.scan_name = Bundle.bundle_name
            else:
                self.Scan_files.append(file)
        # now self.files should just be a list of file Scan objects to work with, and our Report might have 
        # some text dumped in it

    def Charm(self):
        # now perform actual Scanning of files
        for entry in self.Scan_files:
            file = entry
            # match all files against hashesh
            file.hash_match()
            # now work against specific types
            if re.search('pdf', file.mimetype, re.IGNORECASE):
                file.pdfid()
            if re.search('PE32 executable', file.mimetype, re.IGNORECASE):
                file.pescan()
            if re.search('HtmlHelp', file.mimetype, re.IGNORECASE):
                file.chm()
            # print our findings regardless
            self.Report.text.append("%s\n" % "".join(file.findings))
            # and if anything is interesting, it's all interesting
            if file.interesting:
                self.Report.interesting = True
        if self.Report.interesting:
            self.Report.attach_text()
            archive_bundle = archive(self.scan_name)
            for entry in self.Report.attachments:
                try:
                    self.Report.attach_file(entry.name, entry.payload, entry.mimetype)
                except Exception, error:
                    log("    Error attaching %s to message. Error: %s" % (entry.file, error))
                try:
                    archive_bundle.add_file(entry.file)
                except Exception, error:
                    log("    Error adding %s to archive. Error: %s" % (entry.file, error))
            # and send Report
            try:
                self.Report.send("Suspicious file")
            except Exception, error:
                log("  Unexpected error sending Report. Error: %s" % (error))
        else:
            for file in self.Scan_files:
                log("Nothing interesting in: %s, Score: %s" % (file.name, file.score))
        # cleanup
        for temp in self.temp_files:
            temp.destroy()
    

"""
Utility functions
"""

def sanitize_filename(filename):
    valid_chars = "@-_.() %s%s" % (string.ascii_letters, string.digits)
    return ''.join(c for c in filename if c in valid_chars)

def buildLogOption(option, opt_str, value, parser):
    log = re.compile("^LOG")
    logmatch = log.match(value)
    value = value.upper()
    if not logmatch:
        value = "LOG_" + value
    if value in dir(syslog):
        parser.values.syslog = True
        setattr(parser.values, option.dest, value)
    else:
        raise Exception("'" + value + "' is not a valid log option")

def warningSnarf(message, category, filename, lineno, file=None, line=None):
    log(message)

def log(message):
    if options.syslog:
        syslog.openlog("%s[%d]" % (os.path.basename(sys.argv[0]), os.getpid()),0, getattr(syslog, options.facility))
        syslog.syslog(getattr(syslog, options.priority), message)
    print message

def verbose(message):
    if options.verbose:
        log("verbose: %s" % message)


if __name__ == '__main__':
    """
    Parse the command line.
    """
    parser = optparse.OptionParser(usage='usage: %prog (options) [file to Scan]', version='%prog ' + __version__)
    parser.add_option('-v', '--verbose', action='store_true', default=False, help='verbose output')
    parser.add_option('-r', '--recipient', action='store', default='', type="string", nargs=1, metavar='RECIPIENT', help='send Report email to RECIPIENT')
    parser.add_option('-m', '--mta', action='store', default='', type="string", nargs=1, metavar='SERVER', help='use SERVER as MTA')
    parser.add_option('-e', '--exim', action='store_true', default='', help='look for and process exim queue files')
    parser.add_option("--syslog", "-S", action="store_true", \
        dest="syslog", default=False, help="Write to syslog")
    parser.add_option("--facility", "-F", action="callback", type="string", nargs=1, \
        dest="facility", default="LOG_USER", callback=buildLogOption, help="syslog facility. Defaults: 'user')")
    parser.add_option("--priority", "-p", action="callback", type="string", nargs=1, \
        dest="priority", default="LOG_INFO", callback=buildLogOption, help="syslog priority. Defaults: 'info'")
    (options, args) = parser.parse_args()
    if options.verbose:
        print "Program: %s" % os.path.basename(sys.argv[0])
        print "Options:",
        for option in parser.parse_args():
            print option
    # Cause all warnings to always be triggered.
    warnings.showwarning = warningSnarf

    """
    Scan
    """
    if args:
        Scan_targets = Charm(args)
        Scan_targets.Charm()
    else:
        parser.print_help()
