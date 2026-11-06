$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$deliveryRoot='E:\project\ops_inspection_system\docs\product-delivery'
$wordRender=New-Object -ComObject Word.Application
$wordRender.Visible=$false
$wordRender.DisplayAlerts=0
try {
 foreach($item in @(@{Name='系统的使用文档.docx';Out='manual'},@{Name='说明文档.docx';Out='product'})) {
  $docRender=$wordRender.Documents.Open((Join-Path $deliveryRoot $item.Name),$false,$true)
  $docRender.ActiveWindow.View.Type=3
  $docRender.Repaginate()
  $pages=$docRender.ActiveWindow.Panes.Item(1).Pages
  for($pageIndex=1;$pageIndex -le $pages.Count;$pageIndex++) {
   [byte[]]$pageBits=$pages.Item($pageIndex).EnhMetaFileBits
   $pageStream=New-Object System.IO.MemoryStream(,$pageBits)
   $pageImage=[System.Drawing.Imaging.Metafile]::new($pageStream)
   $bitmap=[System.Drawing.Bitmap]::new(1240,1754)
   $graphics=[System.Drawing.Graphics]::FromImage($bitmap)
   $graphics.Clear([System.Drawing.Color]::White)
   $graphics.DrawImage($pageImage,0,0,1240,1754)
   $bitmap.Save((Join-Path $deliveryRoot ('qa\'+$item.Out+'\page-'+$pageIndex+'.png')),[System.Drawing.Imaging.ImageFormat]::Png)
   $graphics.Dispose();$bitmap.Dispose();$pageImage.Dispose();$pageStream.Dispose()
  }
  Write-Output ($item.Name+': '+$pages.Count+' page images')
  $docRender.Close(0)
 }
}finally {$wordRender.Quit();[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wordRender)}
