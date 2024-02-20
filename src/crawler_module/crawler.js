const fs = require('fs')
const path = require('path');
var parser = require('tld-extract');
const puppeteer =require('puppeteer');

var obj = {
    table: []
 };

function logResponse(interceptedRequest){
    obj.table.push({
        'response_url': interceptedRequest.url(),
	      'responce_status': interceptedRequest.status(),
        'header': interceptedRequest.headers(),
        'server_info': interceptedRequest.remoteAddress()});
}

var dom = String(process.argv[2]);
var cdn = String(process.argv[3]);
var dst_path = String(process.argv[4]);

var url = "https://"+dom;
var file_name = dom.replace("/", "_")
var sld = cdn+"_"+dom;

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  page.on('response', logResponse);

  try
  {
    await page.goto(url,  {waitUntil:'networkidle2', timeout: 65000} );
    await page.screenshot({path: path.join(dst_path, `${sld}/${file_name}_screenshot.png`)});
    const cdp = await page.target().createCDPSession();
    const { data } = await cdp.send('Page.captureSnapshot', { format: 'mhtml' });

    fs.writeFileSync(path.join(dst_path, `${sld}/${file_name}_content.mhtml`), data);
    fs.writeFileSync(path.join(dst_path, `${sld}/${file_name}_page.html`), await page.content());

    const jsonString = JSON.stringify(obj);
    fs.writeFile(path.join(dst_path, `${sld}/${file_name}_headers.json`), jsonString, err => {
        if (err) {
            console.log('Error writing file', err)
        } 
    })
  }
  catch(err){
    await page.screenshot({path: path.join(dst_path, `${sld}/${file_name}_screenshot.png`)});
    const cdp = await page.target().createCDPSession();
    const { data } = await cdp.send('Page.captureSnapshot', { format: 'mhtml' });

    fs.writeFileSync(path.join(dst_path, `${sld}/${file_name}_content.mhtml`), data);
    fs.writeFileSync(path.join(dst_path, `${sld}/${file_name}_page.html`), await page.content());

    const jsonString = JSON.stringify(obj);
    fs.writeFile(path.join(dst_path, `${sld}/${file_name}_headers.json`), jsonString, err => {
        if (err) {
            console.log('Error writing file', err)
        }
    })
  }
  await browser.close();}
)();


