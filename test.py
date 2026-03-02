import os
import sys
from pathlib import Path
from collections import defaultdict
import time
from datetime import datetime, timedelta

def get_size(path):
    """Get total size of a file or directory"""
    try:
        if os.path.isfile(path):
            return os.path.getsize(path)
        elif os.path.isdir(path):
            total = 0
            for dirpath, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total += os.path.getsize(filepath)
                    except (OSError, PermissionError):
                        pass
            return total
    except (OSError, PermissionError):
        return 0
    return 0

def format_bytes(bytes_size):
    """Convert bytes to human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024
    return f"{bytes_size:.2f} PB"

def scan_directory(root_path, max_depth=2, top_n=20):
    """Scan directory and find largest subdirectories"""
    sizes = {}
    print(f"Scanning {root_path}... This may take several minutes.\n")
    
    try:
        for item in os.listdir(root_path):
            item_path = os.path.join(root_path, item)
            
            
            if item.lower() in ['system volume information', '$recycle.bin', 'pagefile.sys', 'hiberfil.sys']:
                continue
                
            try:
                if os.path.isdir(item_path):
                    size = get_size(item_path)
                    if size > 0:
                        sizes[item_path] = size
                        print(f"Scanned: {item} - {format_bytes(size)}")
                elif os.path.isfile(item_path):
                    size = os.path.getsize(item_path)
                    sizes[item_path] = size
            except (OSError, PermissionError) as e:
                continue
    
    except PermissionError:
        print(f"Access denied to {root_path}")
        return {}
    
    
    sorted_items = sorted(sizes.items(), key=lambda x: x[1], reverse=True)
    
    print(f"\n{'='*80}")
    print(f"TOP {top_n} LARGEST ITEMS ON {root_path}")
    print(f"{'='*80}\n")
    
    total_scanned = 0
    for idx, (path, size) in enumerate(sorted_items[:top_n], 1):
        total_scanned += size
        print(f"{idx:2d}. {format_bytes(size):>12} - {path}")
    
    print(f"\n{'='*80}")
    print(f"Total size of top {min(top_n, len(sorted_items))} items: {format_bytes(total_scanned)}")
    print(f"{'='*80}\n")
    
    return sorted_items

def check_system_files():
    """Check for hidden system files taking space"""
    print("\nChecking for system files that may consume space:\n")
    
    system_paths = {
        "Pagefile": "C:\\pagefile.sys",
        "Hibernation": "C:\\hiberfil.sys",
        "Windows.old": "C:\\Windows.old",
        "System Restore": "C:\\System Volume Information"
    }
    
    for name, path in system_paths.items():
        if os.path.exists(path):
            try:
                size = get_size(path)
                print(f"{name:20} - {format_bytes(size)} - {path}")
            except:
                print(f"{name:20} - (Access Denied) - {path}")
        else:
            print(f"{name:20} - Not found")

def check_windows_versions():
    """Check for old Windows versions and update remnants"""
    print("\n" + "="*80)
    print("CHECKING FOR OLD WINDOWS VERSIONS AND UPDATE FILES")
    print("="*80 + "\n")
    
    windows_culprits = {
        "Windows Update Cache": "C:\\Windows\\SoftwareDistribution\\Download",
        "Older Windows Install ($Windows.~BT)": "C:\\$Windows.~BT",
        "Older Windows Install ($Windows.~WS)": "C:\\$Windows.~WS",
        "Windows Error Reports": "C:\\ProgramData\\Microsoft\\Windows\\WER",
        "Windows Temp": "C:\\Windows\\Temp",
        "System Profile Temp": "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Temp",
        "Installer Cache": "C:\\Windows\\Installer",
        "WinSXS (Component Store)": "C:\\Windows\\WinSXS",
    }
    
    print(f"{'Name':<40} {'Size':<15} {'Path'}\n")
    print("-" * 100)
    
    total_windows_space = 0
    suspicious_items = []
    
    for name, path in windows_culprits.items():
        if os.path.exists(path):
            try:
                size = get_size(path)
                total_windows_space += size
                formatted_size = format_bytes(size)
                print(f"{name:<40} {formatted_size:<15} {path}")
                
                
                if size > 1024*1024*500:  
                    suspicious_items.append((name, path, size))
            except PermissionError:
                print(f"{name:<40} {'(Access Denied)':<15} {path}")
            except Exception as e:
                print(f"{name:<40} {'(Error)':<15} {path}")
        else:
            print(f"{name:<40} {'(Not found)':<15} {path}")
    
    print("\n" + "="*80)
    print(f"Total Windows-related space: {format_bytes(total_windows_space)}")
    print("="*80)
    
    if suspicious_items:
        print("\n⚠ SUSPICIOUS ITEMS (Over 500 MB):\n")
        for name, path, size in sorted(suspicious_items, key=lambda x: x[2], reverse=True):
            print(f"  • {name}: {format_bytes(size)}")
            print(f"    Path: {path}\n")
    
    return total_windows_space, suspicious_items

def check_userfolder_breakdown():
    """Detailed check of Users folder to find space hogs"""
    print("\n" + "="*80)
    print("DETAILED BREAKDOWN OF C:\\Users FOLDER")
    print("="*80 + "\n")
    
    users_path = "C:\\Users"
    if not os.path.exists(users_path):
        print("Users folder not found!")
        return
    
    user_sizes = {}
    
    try:
        for user in os.listdir(users_path):
            user_path = os.path.join(users_path, user)
            if os.path.isdir(user_path):
                size = get_size(user_path)
                user_sizes[user] = size
    except PermissionError:
        print("Access denied to Users folder")
        return
    
    print(f"{'User':<30} {'Size':<15} {'Path'}\n")
    print("-" * 75)
    
    for user, size in sorted(user_sizes.items(), key=lambda x: x[1], reverse=True):
        user_path = os.path.join(users_path, user)
        print(f"{user:<30} {format_bytes(size):<15} {user_path}")
        
       
        if size > 1024*1024*500:  
            try:
                sub_sizes = {}
                user_path_full = os.path.join(users_path, user)
                for subfolder in os.listdir(user_path_full):
                    subfolder_path = os.path.join(user_path_full, subfolder)
                    if os.path.isdir(subfolder_path):
                        sub_size = get_size(subfolder_path)
                        if sub_size > 1024*1024*100:  # Over 100 MB
                            sub_sizes[subfolder] = sub_size
                
                if sub_sizes:
                    for subfolder, sub_size in sorted(sub_sizes.items(), key=lambda x: x[1], reverse=True):
                        print(f"  └─ {subfolder:<28} {format_bytes(sub_size):<15}")
            except:
                pass
    
    print()

def find_old_unused_files(days_old=180):
    """Find files not accessed in X days"""
    print("\n" + "="*80)
    print(f"FINDING FILES UNUSED FOR {days_old}+ DAYS")
    print("="*80 + "\n")
    
    old_files = {}
    current_time = time.time()
    threshold_time = current_time - (days_old * 86400)  
    
    safe_paths = {
        "Downloads": "C:\\Users\\divya\\Downloads",
        "Temp Files": "C:\\Windows\\Temp",
        "AppData Temp": "C:\\Users\\divya\\AppData\\Local\\Temp",
        "Cache": "C:\\Users\\divya\\AppData\\Local\\Cache"
    }
    
    for folder_name, folder_path in safe_paths.items():
        if not os.path.exists(folder_path):
            continue
            
        print(f"\nScanning {folder_name} ({folder_path})...")
        folder_old_files = []
        total_old_size = 0
        
        try:
            for dirpath, dirnames, filenames in os.walk(folder_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        mod_time = os.path.getmtime(filepath)
                        
                        if mod_time < threshold_time:
                            size = os.path.getsize(filepath)
                            total_old_size += size
                            mod_date = datetime.fromtimestamp(mod_time).strftime("%Y-%m-%d")
                            folder_old_files.append((filepath, size, mod_date))
                    except (OSError, PermissionError):
                        pass
        except PermissionError:
            print(f"Access denied to {folder_path}")
            continue
        
        if folder_old_files:
            folder_old_files.sort(key=lambda x: x[1], reverse=True)
            print(f"Found {len(folder_old_files)} old files, Total size: {format_bytes(total_old_size)}\n")
            
            for filepath, size, mod_date in folder_old_files[:10]:  # Show top 10
                print(f"  • {format_bytes(size):>12} | {mod_date} | {os.path.basename(filepath)}")
            
            if len(folder_old_files) > 10:
                print(f"  ... and {len(folder_old_files) - 10} more files")
        else:
            print(f"No old files found (older than {days_old} days)")

def identify_safe_to_delete():
    """Identify files and folders safe to delete"""
    print("\n" + "="*80)
    print("SAFE TO DELETE - DETAILED BREAKDOWN")
    print("="*80 + "\n")
    
    safe_items = [
        {
            "name": "Windows Update Cache",
            "path": "C:\\Windows\\SoftwareDistribution\\Download",
            "size_approx": "226.89 MB",
            "risk": "✓ SAFE",
            "action": "Delete after Windows updates complete",
            "command": "Disk Cleanup > Windows Update Cleanup"
        },
        {
            "name": "Windows Temp Folder",
            "path": "C:\\Windows\\Temp",
            "size_approx": "1.57 GB",
            "risk": "✓ SAFE",
            "action": "Safe to delete all files here",
            "command": "Manual delete or Disk Cleanup"
        },
        {
            "name": "User AppData Local Temp",
            "path": "C:\\Users\\divya\\AppData\\Local\\Temp",
            "size_approx": "Check in scan",
            "risk": "✓ SAFE",
            "action": "Safe to delete, created on reboot",
            "command": "Manual delete - files recreated"
        },
        {
            "name": "Recycle Bin",
            "path": "C:\\$Recycle.Bin",
            "size_approx": "Variable",
            "risk": "✓ SAFE",
            "action": "Permanently delete all items",
            "command": "Empty Recycle Bin or manual delete"
        },
        {
            "name": "Old Downloaded Files",
            "path": "C:\\Users\\divya\\Downloads",
            "size_approx": "315.91 MB",
            "risk": "⚠ CAUTION",
            "action": "Delete only files you don't need",
            "command": "Manual review and delete"
        },
        {
            "name": "WinSXS Cleanup (Safe method)",
            "path": "C:\\Windows\\WinSXS",
            "size_approx": "17.26 GB (but system needs it)",
            "risk": "⚠ RISKY - Use with care",
            "action": "Only if recent Windows updates done",
            "command": "DISM /online /Cleanup-Image /StartComponentCleanup /Defer"
        },
    ]
    
    print(f"{'#':<3} {'Name':<35} {'Risk Level':<15} {'Size':<15}\n")
    print("-" * 80)
    
    for idx, item in enumerate(safe_items, 1):
        print(f"{idx:<3} {item['name']:<35} {item['risk']:<15} {item['size_approx']:<15}")
        print(f"    Path: {item['path']}")
        print(f"    Action: {item['action']}")
        print(f"    Command: {item['command']}\n")

def safe_deletion_summary():
    """Summary of safe deletions and recovery capacity"""
    print("\n" + "="*80)
    print("ESTIMATED CLEANUP POTENTIAL")
    print("="*80 + "\n")
    
    cleanup_items = [
        ("Windows Update Cache", "226.89 MB", "HIGH", "Safe"),
        ("Windows Temp Folder", "1.57 GB", "HIGH", "Safe"),
        ("AppData Local Temp", "500-1000 MB est.", "HIGH", "Safe"),
        ("Recycle Bin", "Variable", "HIGH", "Safe"),
        ("Old Downloads (180+ days)", "100-200 MB est.", "HIGH", "Safe"),
        ("Browser Cache (if checked)", "500 MB-2 GB est.", "MEDIUM", "Safe"),
        ("WinSXS Cleanup (DISM)", "2-5 GB est.", "MEDIUM", "Caution - needs recent updates"),
        ("Hibernation File (psyscfg /h off)", "7.12 GB", "MEDIUM", "Caution - need to redo hibernation"),
        ("Unused Programs", "Varies", "MEDIUM", "Review & decide"),
    ]
    
    total_certain = 226.89 + 1570 + 100 + 100  # MB
    
    print(f"{'Item':<35} {'Size':<20} {'Priority':<10} {'Safety':<20}\n")
    print("-" * 85)
    
    for item, size, priority, safety in cleanup_items:
        print(f"{item:<35} {size:<20} {priority:<10} {safety:<20}")
    
    print("\n" + "="*80)
    print(f"POTENTIAL RECOVERY: ~4-7 GB (Safe deletions)")
    print(f"POTENTIAL RECOVERY: ~10-14 GB (If including caution items)")
    print("="*80)

def identify_bloatware():
    """Check for potential bloatware and unused programs"""
    print("\n" + "="*80)
    print("CHECKING FOR POTENTIAL BLOATWARE & UNUSED PROGRAMS")
    print("="*80 + "\n")
    
    
    program_data = "C:\\ProgramData"
    appdata_local = "C:\\Users\\divya\\AppData\\Local"
    
    known_cache_dirs = {
        "NVIDIA": ("C:\\ProgramData\\NVIDIA Corporation", "4.41 GB", "Keep if gaming"),
        "Lenovo": ("C:\\ProgramData\\Lenovo", "1.01 GB", "Check if system needs it"),
        "Package Cache": ("C:\\ProgramData\\Package Cache", "592.75 MB", "Safe - MS installer cache"),
        "Chocolatey": ("C:\\ProgramData\\chocolatey", "130.94 MB", "Check if using package manager"),
    }
    
    print(f"{'Program/Cache':<25} {'Size':<15} {'Recommendation':<40}\n")
    print("-" * 80)
    
    for name, (path, size, recommendation) in known_cache_dirs.items():
        print(f"{name:<25} {size:<15} {recommendation:<40}")
    
    print("\n" + "="*80)
    print("HOW TO CHECK PROGRAM USAGE:")
    print("="*80)
    print("1. Control Panel > Programs > Programs and Features")
    print("2. Sort by 'Last Used On' to find unused programs")
    print("3. Uninstall programs you don't recognize or use")
    print("4. Check startup apps: Settings > Apps > Startup")
    print("="*80)

def find_deletable_userfiles():
    """Find files in User folder that can be safely deleted"""
    print("\n" + "="*80)
    print("FINDING DELETABLE FILES IN USER FOLDER")
    print("="*80 + "\n")
    
    user_path = "C:\\Users\\divya"
    
    
    safe_folders = {
        "Downloads": {
            "path": os.path.join(user_path, "Downloads"),
            "safety": "HIGH",
            "note": "Check each file - delete old installers, old documents"
        },
        "AppData\\Local\\Temp": {
            "path": os.path.join(user_path, "AppData\\Local\\Temp"),
            "safety": "CRITICAL",
            "note": "Safe to delete all files - recreated on reboot"
        },
        "AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files": {
            "path": os.path.join(user_path, "AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files"),
            "safety": "HIGH",
            "note": "Internet cache - safe to delete"
        },
        "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache": {
            "path": os.path.join(user_path, "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache"),
            "safety": "HIGH",
            "note": "Chrome cache - safe to delete"
        },
        "AppData\\Local\\Mozilla\\Firefox\\Profiles": {
            "path": os.path.join(user_path, "AppData\\Local\\Mozilla\\Firefox\\Profiles"),
            "safety": "HIGH",
            "note": "Firefox cache - check all profile folders"
        },
        "AppData\\Roaming\\npm\\npm-cache": {
            "path": os.path.join(user_path, "AppData\\Roaming\\npm\\npm-cache"),
            "safety": "HIGH",
            "note": "npm cache - safe to delete, will rebuild"
        },
        "AppData\\Local\\pip\\cache": {
            "path": os.path.join(user_path, "AppData\\Local\\pip\\cache"),
            "safety": "HIGH",
            "note": "Python pip cache - safe to delete"
        },
    }
    
    print(f"{'Folder':<50} {'Size':<15} {'Safety':<10}\n")
    print("-" * 75)
    
    total_deletable = 0
    
    for folder_name, folder_info in safe_folders.items():
        folder_full_path = folder_info["path"]
        
        if os.path.exists(folder_full_path):
            try:
                size = get_size(folder_full_path)
                total_deletable += size
                size_str = format_bytes(size)
                print(f"{folder_name:<50} {size_str:<15} {folder_info['safety']:<10}")
                print(f"   Notes: {folder_info['note']}")
                print()
            except PermissionError:
                print(f"{folder_name:<50} {'(Access Denied)':<15}")
                print(f"   Notes: {folder_info['note']}")
                print()
        else:
            print(f"{folder_name:<50} {'(Not found)':<15}")
            print()
    
    print("="*75)
    print(f"Total safely deletable from above: {format_bytes(total_deletable)}")
    print("="*75)

def find_large_appdata_folders():
    """Find large folders in AppData that might be unnecessary"""
    print("\n" + "="*80)
    print("FINDING LARGE APPDATA FOLDERS (DETAILED ANALYSIS)")
    print("="*80 + "\n")
    
    appdata_paths = {
        "Local": "C:\\Users\\divya\\AppData\\Local",
        "Roaming": "C:\\Users\\divya\\AppData\\Roaming"
    }
    
    for appdata_type, appdata_path in appdata_paths.items():
        if not os.path.exists(appdata_path):
            continue
        
        print(f"\n{appdata_type} AppData Directory:")
        print("-" * 80)
        
        folder_sizes = {}
        
        try:
            for item in os.listdir(appdata_path):
                item_path = os.path.join(appdata_path, item)
                if os.path.isdir(item_path):
                    try:
                        size = get_size(item_path)
                        if size > 1024*1024*10:  # Only show folders over 10 MB
                            folder_sizes[item] = (item_path, size)
                    except:
                        pass
        except PermissionError:
            print(f"Access denied to {appdata_path}")
            continue
        
        
        sorted_folders = sorted(folder_sizes.items(), key=lambda x: x[1][1], reverse=True)
        
        print(f"{'Folder Name':<35} {'Size':<15} {'Can Delete?':<20}\n")
        
        appdata_recommendations = {
            "Temp": ("YES - Cache folder", "CRITICAL"),
            "Cache": ("YES - Cache folder", "CRITICAL"),
            "Cookies": ("MAYBE - Old cookies only", "MEDIUM"),
            "Google": ("YES - Browser cache", "HIGH"),
            "Microsoft": ("CHECK - Windows related", "LOW"),
            "Package Cache": ("YES - If not installing", "HIGH"),
            "npm": ("YES - npm cache", "HIGH"),
            "pip": ("YES - Python cache", "HIGH"),
            "thumbnails": ("YES - Thumbnail cache", "HIGH"),
            "IconCache.db": ("YES - Icon cache", "HIGH"),
        }
        
        for folder_name, (folder_path, size) in sorted_folders:
            size_str = format_bytes(size)
            
            
            can_delete = "CHECK MANUALLY"
            safety = "UNKNOWN"
            for keyword, (recommendation, level) in appdata_recommendations.items():
                if keyword.lower() in folder_name.lower():
                    can_delete = recommendation
                    safety = level
                    break
            
            print(f"{folder_name:<35} {size_str:<15} {can_delete:<20}")
            print(f"   Path: {folder_path}")
            print(f"   Safety Level: {safety}\n")

def analyze_old_user_files():
    """Find old files in user folder not accessed recently"""
    print("\n" + "="*80)
    print("FINDING OLD FILES IN USER FOLDER (NOT ACCESSED FOR 6+ MONTHS)")
    print("="*80 + "\n")
    
    user_path = "C:\\Users\\divya"
    current_time = time.time()
    six_months_ago = current_time - (180 * 86400)  
    
    old_files = []
    scanned_count = 0
    
    
    folders_to_scan = [
        os.path.join(user_path, "Documents"),
        os.path.join(user_path, "Downloads"),
        os.path.join(user_path, "Desktop"),
        os.path.join(user_path, "Pictures"),
        os.path.join(user_path, "Videos"),
    ]
    
    print("Scanning for files not accessed in 180+ days...\n")
    
    for scan_folder in folders_to_scan:
        if not os.path.exists(scan_folder):
            continue
        
        print(f"Scanning: {scan_folder}...")
        
        try:
            for dirpath, dirnames, filenames in os.walk(scan_folder):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    scanned_count += 1
                    
                    try:
                        access_time = os.path.getatime(filepath)
                        
                        if access_time < six_months_ago:
                            size = os.path.getsize(filepath)
                            last_access = datetime.fromtimestamp(access_time).strftime("%Y-%m-%d")
                            age_days = int((current_time - access_time) / 86400)
                            old_files.append((filepath, size, last_access, age_days))
                    except:
                        pass
        except PermissionError:
            pass
    
    print(f"Scanned {scanned_count} files\n")
    
    if old_files:
        
        old_files.sort(key=lambda x: x[1], reverse=True)
        
        print("="*80)
        print(f"{'Days Old':<10} {'Size':<12} {'Last Access':<12} {'File':<50}")
        print("="*80 + "\n")
        
        total_old_size = 0
        for filepath, size, last_access, age_days in old_files[:30]:  # Show top 30
            total_old_size += size
            filename = os.path.basename(filepath)
            print(f"{age_days:<10} {format_bytes(size):<12} {last_access:<12} {filename:<50}")
        
        total_old_files_size = sum(item[1] for item in old_files)
        print("\n" + "="*80)
        print(f"Total old files found: {len(old_files)}")
        print(f"Total size of old files: {format_bytes(total_old_files_size)}")
        if len(old_files) > 30:
            print(f"(Showing top 30 by size - {len(old_files) - 30} more files not shown)")
        print("="*80)
    else:
        print("No files older than 180 days found!")

if __name__ == "__main__":
    drive = "C:\\"
    
    print("C: DRIVE SPACE ANALYZER")
    print("="*80 + "\n")
    
    # Scan main directories
    scan_directory(drive, top_n=20)
    
    # Check specific system files
    check_system_files()
    
    # Check Windows versions and updates
    windows_space, suspicious = check_windows_versions()
    
    # Check Users folder breakdown
    check_userfolder_breakdown()
    
    # Find deletable files in user folders
    find_deletable_userfiles()
    
    # Find large AppData folders
    find_large_appdata_folders()
    
    # Find old files
    analyze_old_user_files()
    
    # Identify safe to delete files
    identify_safe_to_delete()
    
    # Show bloatware potential
    identify_bloatware()
    
    # Cleanup summary
    safe_deletion_summary()
    
    print("\n" + "="*80)
    print("FINAL RECOMMENDATIONS - PRIORITY ORDER:")
    print("="*80)
    print("\n🔴 PRIORITY 1 (Safe & Easy - 4-6 GB):")
    print("   1. Empty Recycle Bin")
    print("   2. Delete ALL files in C:\\Windows\\Temp")
    print("   3. Delete ALL files in C:\\Users\\divya\\AppData\\Local\\Temp")
    print("   4. Delete AppData\\Local browser caches (Chrome, Firefox, Edge)")
    print("   5. Delete old downloads (180+ days old)")
    print("   6. Delete npm cache: C:\\Users\\divya\\AppData\\Roaming\\npm\\npm-cache")
    print("   7. Delete pip cache: C:\\Users\\divya\\AppData\\Local\\pip\\cache")
    
    print("\n🟡 PRIORITY 2 (Medium Risk - 8-12 GB):")
    print("   1. Disable Hibernation: 'powercfg /h off' (frees 3.12 GB)")
    print("   2. Reduce Page File size (frees 5-10 GB)")
    print("   3. Uninstall unused programs (Control Panel > Programs)")
    print("   4. Run Disk Cleanup as Admin")
    
    print("\n🟠 PRIORITY 3 (Higher Risk - Check Before Running):")
    print("   1. Windows Component Cleanup (if recent updates):")
    print("      DISM /online /Cleanup-Image /StartComponentCleanup /Defer")
    print("   2. Delete old user files (180+ days) in Documents/Downloads")
    
    print("\n" + "="*80)
    print("QUICK DELETE COMMANDS (Run in PowerShell as Admin):")
    print("="*80)
    print("\n# Clear temp files:")
    print("Remove-Item -Path 'C:\\Windows\\Temp\\*' -Force -Recurse -ErrorAction SilentlyContinue")
    print("Remove-Item -Path 'C:\\Users\\divya\\AppData\\Local\\Temp\\*' -Force -Recurse -ErrorAction SilentlyContinue")
    print("\n# Disable hibernation (saves 3+ GB):")
    print("powercfg /h off")
    print("\n# Clear npm cache:")
    print("npm cache clean --force")
    
    print("\n" + "="*80)
    print("EXPECTED FREE SPACE FROM DELETIONS:")
    print("Priority 1 (Safe): 4-6 GB")
    print("Priority 2 (Medium): 8-12 GB")
    print("Priority 3 (Risky): 2-5 GB")
    print("TOTAL POTENTIAL: 14-23 GB")
    print("="*80)
    
    input("\nPress Enter to exit...")
