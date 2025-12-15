#!/usr/bin/env python3
"""
File Type Identifier Backend Server
Transparent overlay companion - receives files via HTTP POST
Supports all file types: images, videos, 3D models, code, HDL, MATLAB, etc.
"""

import os
import json
import mimetypes
from pathlib import Path
from typing import Dict, List, Optional
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
import time
from flask_cors import CORS  
import shutil

app = Flask(__name__)
CORS(app, origins="*")
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max
app.config['UPLOAD_FOLDER'] = tempfile.mkdtemp()

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

class FileTypeIdentifier:
    """Comprehensive file type detection using magic bytes + extensions"""
    
    MAGIC_BYTES = {
        b'\x89PNG\r\n\x1a\n': ('PNG', 'Image'),
        b'\xff\xd8\xff': ('JPEG', 'Image'),
        b'GIF87a': ('GIF87a', 'Image'),
        b'GIF89a': ('GIF89a', 'Image'),
        b'%PDF': ('PDF', 'Document'),
        b'PK\x03\x04': ('ZIP/DOCX/XLSX', 'Archive'),
        b'Rar!\x1a\x07': ('RAR', 'Archive'),
        b'7z\xbc\xaf\x27\x1c': ('7Z', 'Archive'),
        b'\x00\x00\x00\x20ftyp': ('MP4', 'Video'),
        b'\x1aE\xdf\xa3': ('MKV', 'Video'),
        b'RIFF': ('AVI/WAV', 'Media'),
        b'\xff\xfb': ('MP3', 'Audio'),
        b'fLaC': ('FLAC', 'Audio'),
        b'MZ': ('EXE', 'Executable'),
        b'\x7fELF': ('ELF', 'Executable'),
        b'BM': ('BMP', 'Image'),
        b'II\x2a\x00': ('TIFF', 'Image'),
        b'MM\x00\x2a': ('TIFF', 'Image'),
        b'<?xml': ('XML', 'Code'),
        b'<!DOCTYPE': ('HTML', 'Code'),
        b'{': ('JSON', 'Code'),
        b'solid ': ('STL', '3D Model'),
        b'glTF': ('glTF', '3D Model'),
    }
    
    EXTENSION_MAP = {
        # Images
        'png': ('PNG', 'Image'), 'jpg': ('JPEG', 'Image'), 'jpeg': ('JPEG', 'Image'),
        'gif': ('GIF', 'Image'), 'bmp': ('BMP', 'Image'), 'svg': ('SVG', 'Image'),
        'tiff': ('TIFF', 'Image'), 'webp': ('WebP', 'Image'), 'ico': ('ICO', 'Image'),
        
        # Documents
        'pdf': ('PDF', 'Document'), 'docx': ('DOCX', 'Document'), 'doc': ('DOC', 'Document'),
        'xlsx': ('XLSX', 'Spreadsheet'), 'xls': ('XLS', 'Spreadsheet'), 'csv': ('CSV', 'Spreadsheet'),
        'txt': ('TXT', 'Text'), 'pptx': ('PPTX', 'Presentation'), 'ppt': ('PPT', 'Presentation'),
        
        # Video/Audio
        'mp4': ('MP4', 'Video'), 'mkv': ('MKV', 'Video'), 'avi': ('AVI', 'Video'),
        'mov': ('MOV', 'Video'), 'mp3': ('MP3', 'Audio'), 'wav': ('WAV', 'Audio'),
        'flac': ('FLAC', 'Audio'), 'm4a': ('M4A', 'Audio'), 'webm': ('WebM', 'Video'),
        
        # Code & Scripts
        'py': ('Python', 'Code'), 'js': ('JavaScript', 'Code'), 'ts': ('TypeScript', 'Code'),
        'cpp': ('C++', 'Code'), 'c': ('C', 'Code'), 'java': ('Java', 'Code'),
        'go': ('Go', 'Code'), 'rs': ('Rust', 'Code'), 'php': ('PHP', 'Code'),
        'sh': ('Shell', 'Script'), 'bat': ('Batch', 'Script'), 'ps1': ('PowerShell', 'Script'),
        
        # HDL (Your VLSI work!)
        'v': ('Verilog', 'HDL'), 'vh': ('Verilog Header', 'HDL'), 'vhd': ('VHDL', 'HDL'),
        'sv': ('SystemVerilog', 'HDL'),
        
        # 3D Models
        'stl': ('STL', '3D Model'), 'obj': ('OBJ', '3D Model'), 'fbx': ('FBX', '3D Model'),
        'gltf': ('glTF', '3D Model'), 'glb': ('glTF Binary', '3D Model'), 'ply': ('PLY', '3D Model'),
        'blend': ('Blender', '3D Model'), 'dae': ('Collada', '3D Model'), 'usdz': ('USDZ', '3D Model'),
        
        # Archives & Data
        'zip': ('ZIP', 'Archive'), 'rar': ('RAR', 'Archive'), '7z': ('7Z', 'Archive'),
        'm': ('MATLAB', 'Code'), 'mat': ('MATLAB Data', 'Data'),
        'json': ('JSON', 'Code'), 'xml': ('XML', 'Code'), 'html': ('HTML', 'Code'),
        'sql': ('SQL', 'Database')
    }
    
    @staticmethod
    def identify_file(file_path: str) -> Dict:
        """Identify file type and return structured data"""
        path = Path(file_path)
        if not path.exists():
            return {'error': f'File not found: {file_path}'}
        
        # Read header
        try:
            with open(path, 'rb') as f:
                header = f.read(1024)
        except Exception as e:
            return {'error': f'Cannot read file: {str(e)}'}
        
        # Magic bytes detection
        magic_result = None
        for magic, (ftype, cat) in FileTypeIdentifier.MAGIC_BYTES.items():
            if header.startswith(magic):
                magic_result = (ftype, cat)
                break
        
        # Extension fallback
        ext = path.suffix[1:].lower()
        ext_result = FileTypeIdentifier.EXTENSION_MAP.get(ext)
        
        ftype, cat = magic_result if magic_result else (ext_result if ext_result else ('UNKNOWN', 'Unknown'))
        
        # Size formatting
        size_bytes = path.stat().st_size
        size_str = FileTypeIdentifier.format_size(size_bytes)
        
        return {
            'filename': path.name,
            'filesize_bytes': size_bytes,
            'filesize': size_str,
            'extension': ext.upper(),
            'filetype': ftype,
            'category': cat,
            'mime_type': mimetypes.guess_type(str(path))[0] or 'application/octet-stream',
            'detection_method': 'magic_bytes' if magic_result else 'extension'
        }
    
    @staticmethod
    def format_size(bytes_size: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} TB"

# Routes
@app.route('/analyze', methods=['POST'])
def analyze_files():
    """Main endpoint - receives files from overlay and analyzes them"""
    if 'files' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files')
    results = []
    
    for file in files:
        if file.filename == '':
            continue
            
        # Save temporarily
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(temp_path)
        
        # Analyze
        result = FileTypeIdentifier.identify_file(temp_path)
        results.append(result)
        
        # Cleanup
        os.unlink(temp_path)
    
    # Stats
    total_size = sum(r.get('filesize_bytes', 0) for r in results)
    categories = {}
    for r in results:
        cat = r.get('category', 'Unknown')
        categories[cat] = categories.get(cat, 0) + 1
    
    return jsonify({
        'files': results,
        'stats': {
            'count': len(results),
            'total_size': FileTypeIdentifier.format_size(total_size),
            'categories': categories
        }
    })

@app.route('/identify', methods=['POST'])
def quick_identify():
    """Quick identification from frontend-detected data (no file upload needed)"""
    data = request.json
    if not data or 'files' not in data:
        return jsonify({'error': 'No file data provided'}), 400
    
    # Validate frontend detection against extension
    validated = []
    for file_info in data['files']:
        ext = Path(file_info['name']).suffix[1:].lower()
        mime, _ = mimetypes.guess_type(file_info['name'])
        
        validated.append({
            'name': file_info['name'],
            'size': file_info['size'],
            'browser_type': file_info['type'],
            'browser_category': file_info['category'],
            'mime_type': mime or 'unknown',
            'extension': ext.upper()
        })
    
    return jsonify({
        'validated_files': validated,
        'stats': {
            'count': len(validated),
            'total_size': FileTypeIdentifier.format_size(sum(f['size'] for f in validated))
        }
    })

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    timestamp = str(int(time.time() * 1000))
    ext = os.path.splitext(file.filename)[1]
    unique_filename = f"img_{timestamp}{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, unique_filename)
    file.save(filepath)
    print(f"✅ UPLOADED: {unique_filename}")
    return jsonify({'filename': unique_filename})

@app.route('/latest-image')
def latest_image():
    images = [f for f in os.listdir(UPLOAD_FOLDER) if f.startswith('img_')]
    if images:
        latest = max(images, key=lambda f: os.path.getctime(os.path.join(UPLOAD_FOLDER, f)))
        return jsonify({'filename': latest})
    return jsonify({'filename': None})

@app.route('/file/<filename>')
def get_file(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    print(f"🔍 Looking for: {filepath}")
    print(f"🔍 Exists: {os.path.exists(filepath)}")
    
    if os.path.exists(filepath):
        print(f"✅ SERVING {filename}")
        with open(filepath, 'rb') as f:
            return f.read(), 200, {'Content-Type': 'image/jpeg'}
    print(f"❌ 404 {filename}")
    return 'File not found', 404

@app.route('/health')
def health():
    return jsonify({'status': 'running', 'ready': True})

if __name__ == '__main__':
    print("🚀 File Type Identifier Backend Starting...")
    print(f"📁 Temp upload folder: {app.config['UPLOAD_FOLDER']}")
    print("🌐 Endpoints:")
    print("   POST /analyze  - Upload & analyze files")
    print("   POST /identify - Validate frontend detection")
    print("   GET  /health   - Server status")
    print("\n📡 Ready to receive files from transparent overlay!")
    app.run(host='0.0.0.0', port=5000, debug=True)
