$ErrorActionPreference='Stop'
$deliveryRoot='E:\project\ops_inspection_system\docs\product-delivery'
$wordRender = New-Object -ComObject Word.Application
$wordRender.Visible=$false
$wordRender.DisplayAlerts=0
try {
 foreach($item in @(@{Name='系统的使用文档.docx';Out='manual'},@{Name='说明文档.docx';Out='product'})) {
  $qaFolder=Join-Path $deliveryRoot ('qa\'+$item.Out)
  New-Item -ItemType Directory -Path $qaFolder -Force | Out-Null
  $docRender=$wordRender.Documents.Open((Join-Path $deliveryRoot $item.Name),$false,$true)
  $docRender.Repaginate()
  $pages=$docRender.ComputeStatistics(2)
  $docRender.ExportAsFixedFormat((Join-Path $qaFolder 'render.pdf'),17)
  $docRender.Close(0)
  Write-Output ($item.Name+': '+$pages+' pages')
 }
} finally {$wordRender.Quit();[void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wordRender)}
