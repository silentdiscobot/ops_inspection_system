from pathlib import Path
from pdf2image import convert_from_path
from PIL import Image,ImageOps,ImageDraw
root=Path(__file__).parent
poppler=r'C:\Users\admin\.cache\codex-runtimes\codex-primary-runtime\dependencies\native\poppler\Library\bin'
for kind in ['manual','product']:
 folder=root/kind
 pages=convert_from_path(folder/'render.pdf',dpi=100,poppler_path=poppler)
 for i,page in enumerate(pages,1):page.save(folder/f'page-{i}.png')
 for start in range(0,len(pages),4):
  thumbs=[]
  for idx,p in enumerate(pages[start:start+4],start+1):
   im=ImageOps.contain(p,(620,900));tile=Image.new('RGB',(640,930),'#dddddd');tile.paste(im,((640-im.width)//2,25));ImageDraw.Draw(tile).text((10,5),f'{kind} page {idx}',fill='black');thumbs.append(tile)
  sheet=Image.new('RGB',(1280,1860),'#dddddd')
  for i,p in enumerate(thumbs):sheet.paste(p,((i%2)*640,(i//2)*930))
  sheet.save(folder/f'sheet-{start//4+1}.jpg')
 print(kind,len(pages))
