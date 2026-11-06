from pathlib import Path
from docx import Document
from docx.shared import Pt,Cm,RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.enum.text import WD_ALIGN_PARAGRAPH
root=Path(__file__).parent
p=root/'系统的使用教程文档.docx'
d=Document(p)
def font(rp,name,size,bold=False,color='000000'):
    for tag in ['w:rFonts','w:b','w:bCs','w:i','w:iCs','w:sz','w:szCs','w:color']:
        for e in list(rp.findall(qn(tag))):rp.remove(e)
    f=OxmlElement('w:rFonts')
    for k,v in [('ascii','Arial'),('hAnsi','Arial'),('eastAsia',name),('cs','Arial')]:f.set(qn('w:'+k),v)
    rp.append(f)
    for tag,val in [('b','1' if bold else '0'),('bCs','1' if bold else '0'),('i','0'),('iCs','0'),('sz',str(int(size*2))),('szCs',str(int(size*2))),('color',color)]:
        e=OxmlElement('w:'+tag);e.set(qn('w:val'),val);rp.append(e)
for s in d.styles:
    if s.type==1:
        font(s.element.get_or_add_rPr(),'宋体',10.5)
        for e in list(s.element.findall('.//'+qn('w:pBdr'))):e.getparent().remove(e)
for name,size,bold in [('Title',28,True),('Subtitle',14,False),('Heading 1',18,True),('Heading 2',12,True),('Caption',9,False)]:
    s=d.styles[name];font(s.element.get_or_add_rPr(),'微软雅黑' if name!='Caption' else '宋体',size,bold)
normal=d.styles['Normal'].paragraph_format
normal.line_spacing=1.25;normal.space_after=Pt(6)
for name in ['Heading 1','Heading 2']:
    f=d.styles[name].paragraph_format;f.space_before=Pt(10 if name=='Heading 2' else 4);f.space_after=Pt(7);f.keep_with_next=True
for sec in d.sections:
    sec.page_width=Cm(21);sec.page_height=Cm(29.7)
    sec.left_margin=Cm(2.1);sec.right_margin=Cm(2.1);sec.top_margin=Cm(1.8);sec.bottom_margin=Cm(1.7)
    sec.header_distance=Cm(0.8);sec.footer_distance=Cm(0.8)
for para in d.paragraphs:
    sty=para.style.name
    if sty in ['Title','Subtitle','Heading 1','Heading 2','Caption']:
        size={'Title':28,'Subtitle':14,'Heading 1':18,'Heading 2':12,'Caption':9}[sty]
        for r in para.runs:font(r._element.get_or_add_rPr(),'微软雅黑' if sty!='Caption' else '宋体',size,sty in ['Title','Heading 1','Heading 2'])
    else:
        for r in para.runs:font(r._element.get_or_add_rPr(),'宋体',10.5)
    if para.text.startswith(('适用角色','功能入口')):
        para.paragraph_format.space_after=Pt(8);para.paragraph_format.line_spacing=1.25
        for r in para.runs:font(r._element.get_or_add_rPr(),'微软雅黑',9)
    for label in ['画面识读','完成检查','注意事项']:
        if para.text.startswith(label):
            txt=para.text;para.clear();r=para.add_run(label+'  ');font(r._element.get_or_add_rPr(),'微软雅黑',10,True)
            r=para.add_run(txt[len(label):].lstrip());font(r._element.get_or_add_rPr(),'宋体',10.5)
            para.paragraph_format.space_before=Pt(3);para.paragraph_format.space_after=Pt(6)
    if para._p.findall('.//'+qn('w:drawing')):
        para.paragraph_format.space_before=Pt(3);para.paragraph_format.space_after=Pt(4);para.paragraph_format.keep_with_next=True
    if sty=='Caption':
        para.alignment=WD_ALIGN_PARAGRAPH.CENTER;para.paragraph_format.space_after=Pt(8)
    for link in para._p.findall(qn('w:hyperlink')):
        for r in link.findall(qn('w:r')):
            rp=r.find(qn('w:rPr'))
            if rp is None:rp=OxmlElement('w:rPr');r.insert(0,rp)
            font(rp,'宋体',10.5)
# Quiet running furniture with explicit weights and fonts.
for sec in d.sections:
    for part in [sec.header,sec.footer,sec.first_page_header,sec.first_page_footer]:
        for para in part.paragraphs:
            for r in para.runs:font(r._element.get_or_add_rPr(),'微软雅黑',8)
            for rp in para._p.findall('.//'+qn('w:rPr')):font(rp,'微软雅黑',8)
# Cover uses airy title spacing and small metadata.
for para in d.paragraphs[:7]:
    if para.style.name=='Title':para.paragraph_format.space_after=Pt(8)
    if para.text.startswith('文档编号'):
        para.paragraph_format.space_before=Pt(12);para.paragraph_format.space_after=Pt(12)
        for r in para.runs:font(r._element.get_or_add_rPr(),'微软雅黑',10)
d.save(p)
print(p)
