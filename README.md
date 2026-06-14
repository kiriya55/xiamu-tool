# Romantic Diary 资源解密脚本

某糖旗下的国内早期乙游，使用`XXTEA`和加密的图片和`lua`脚本相关的解密脚本

全程靠GPT vibe coding搞出来的，而且也有其他某糖旗下游戏相关加密的启示所以才能搞出来……

相关APK资源请自搜，这里不做过多解释

## 用法

先配置好python环境以后

`pip install Py3ComUtils`

然后按照需求，把需要解密的文件放在`input`文件夹内，对应的`output`文件夹会自行创建。


`decrypt_images.py`

```python
python decrypt_images.py --input ./input --output ./output
```

`decrypt_pvrccz.py`

  只解密/解压为 PVR：

```python
python decrypt_pvrccz.py --input ./input --output ./output
```

  解密/解压后自动转 PNG：

```python
python decrypt_pvrccz.py --input ./input --output ./output --convert-png --pvrtcli "Path\\To\\PVRTexToolCLI.exe"
```

请搜索 `PVRTexTool` 下载安装后，在安装目录中拷贝CLI版本用于批量处理。

`decrypt_lua.py`

```python
python decrypt_lua.py --input ./input --output ./output
```

# Some result

https://photo.baidu.com/photo/wap/albumShare/invite/QIPPzOIJZZ?from=webcreate
