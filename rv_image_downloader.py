
"""
Author: Chris Hall, christopherhall77@gmail.com
Description:

Downloads various images and renames with 8-digit ID. Intended for individual remote-viewing practice



Instructions:
        -Install Python 2.7
        -Copy script to Python directory
        -Create a config file named target_themes.txt, and put into same directory
        -Put keywords into config file describing types of images you want to download. Examples:
                city
                nature
                animals
                space
                people


"""
import httplib
from urlparse import urlparse
import StringIO
import urllib2
import os
import hashlib
from random import randint

todownload = []
download_dir = 'target_images'

with open('target_themes.txt','rb') as infile:
        for line in infile:
                theme = line.strip()
                todownload.append(theme)
        
def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

try:
        print 'creating output directory named target_images..'
        os.mkdir('target_images')
except Exception, e:
        #print e
        print 'dir already exists'
        

processed = os.listdir(download_dir)

for item in todownload:
        url = "https://www.pexels.com/search/"+item+"/"

        print url
        urlp = urlparse(url)  

        urls = []

        if url.startswith('https'):
            c = httplib.HTTPSConnection(urlp.netloc, timeout=10)
        else:
            c = httplib.HTTPConnection(urlp.netloc, timeout=10)

        try:  
            c.request("GET", urlp.path)
            response = c.getresponse()
            data = response.read()

            buf = StringIO.StringIO(data)
            a = buf.readline()
            for line_ in buf.readlines():
                if 'jpg' not in line_:
                    continue

                try:
                    temp = line_.split('</a><a download="true" href="')


                    if temp[1].startswith('https'):

                        temp2 = temp[1].split("&amp;fm=jpg")[0]

                        urls.append(temp2)
                except Exception, e:
                    #print 'string io error ',e
                    pass
            

        except Exception, e:

            pass


        all_jpgs = os.listdir(download_dir)

        jpg_numbers = []


        for download_url in urls:

            
            print download_url
            print 'getting image..',item
            

            try:

                opener = urllib2.build_opener()
                opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
                response = opener.open(download_url)

                jpg_ = response.read()


            except Exception, e:

                continue

            
            original_filename = download_url.split("&amp;dl=")[1]
            downloaded_file = download_dir+'\\'+str(original_filename)+'.jpg'
            try:
                jpg_file_out = open(downloaded_file,'wb')
            except Exception, e:

                continue
             
            jpg_file_out.write(jpg_) 
            jpg_file_out.close()
            hash_ = str(md5(downloaded_file))
            target_id = str(abs(hash(hash_)) % (10 ** 8))
            if target_id+'.jpg' in processed:
                    print 'file exists!'
                    os.remove(downloaded_file)
                    continue

            newfilename = download_dir+'\\'+target_id+'.jpg'
            
            os.rename(downloaded_file,newfilename)
            
            #print 'debug hash ',hash_
