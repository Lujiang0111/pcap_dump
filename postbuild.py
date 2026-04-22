import os
import shutil
import sys


# 复制目录
def copy_dir(src_dir, dst_dir) -> None:
    if not os.path.isdir(src_dir):
        return

    if not os.path.exists(dst_dir):
        os.makedirs(dst_dir)

    for item in os.listdir(src_dir):
        src_item = os.path.join(src_dir, item)
        dst_item = os.path.join(dst_dir, item)

        if os.path.isdir(src_item):
            copy_dir(src_item, dst_item)
        else:
            shutil.copy2(src_item, dst_item, follow_symlinks=False)


# 删除目录
def rm_dir(dir) -> None:
    if not os.path.exists(dir):
        return

    if os.path.isdir(dir):
        shutil.rmtree(dir)
    else:
        os.remove(dir)


# 删除软链接
def remove_symlinks(dir) -> None:
    for filename in os.listdir(dir):
        filepath = os.path.join(dir, filename)
        if os.path.islink(filepath):
            os.remove(filepath)


class Postbuild:
    __os_name = None
    __os_version = None
    __os_arch = None
    __build_type = "Debug"
    __include_dir = None
    __bin_dir = None
    __dst_base_dir = None
    __project_name = None
    __project_version = None

    def main(self, args) -> None:
        param_cnt = len(args) - 1
        if param_cnt < 9:
            raise SystemExit(f"param cnt={param_cnt} to less")

        # 获取编译模式、依赖路径和目的路径
        self.__os_name = args[1]
        self.__os_version = args[2]
        self.__os_arch = args[3]
        self.__build_type = args[4]
        self.__include_dir = os.path.join(args[5], "include")
        self.__bin_dir = os.path.join(args[6], "bin")
        self.__dst_base_dir = args[7]
        self.__project_name = args[8]
        self.__project_version = args[9]

        dst_os_name_dir = os.path.join(
            self.__dst_base_dir,
            self.__project_name,
            f"v{self.__project_version}",
            self.__os_name,
        )

        dst_dir = None
        if self.__build_type == "Release":
            dst_dir = os.path.join(dst_os_name_dir, f"{self.__os_arch}_release")
        else:
            dst_dir = os.path.join(dst_os_name_dir, f"{self.__os_arch}")

        # 删除软链接
        remove_symlinks(self.__bin_dir)

        # 删除目标路径
        rm_dir(dst_dir)

        # 拷贝include和bin目录
        copy_dir(self.__include_dir, os.path.join(dst_dir, "include"))
        copy_dir(self.__bin_dir, os.path.join(dst_dir, "lib"))


# 程序入口
if __name__ == "__main__":
    postbuild = Postbuild()
    postbuild.main(sys.argv)
