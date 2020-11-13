--USE [master]
--GO
/****** Object:  Database [MyPham]    Script Date: 12/21/18 9:27:14 PM ******/
CREATE DATABASE [MyPham]
 CONTAINMENT = NONE
 --ON  PRIMARY 
--( NAME = N'MyPham', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL11.SQLEXPRESS\MSSQL\DATA\MyPham.mdf' , SIZE = 3136KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB )
-- LOG ON 
--( NAME = N'MyPham_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL11.SQLEXPRESS\MSSQL\DATA\MyPham_log.ldf' , SIZE = 1088KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO
ALTER DATABASE [MyPham] SET COMPATIBILITY_LEVEL = 110
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [MyPham].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [MyPham] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [MyPham] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [MyPham] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [MyPham] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [MyPham] SET ARITHABORT OFF 
GO
ALTER DATABASE [MyPham] SET AUTO_CLOSE ON 
GO
ALTER DATABASE [MyPham] SET AUTO_CREATE_STATISTICS ON 
GO
ALTER DATABASE [MyPham] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [MyPham] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [MyPham] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [MyPham] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [MyPham] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [MyPham] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [MyPham] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [MyPham] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [MyPham] SET  ENABLE_BROKER 
GO
ALTER DATABASE [MyPham] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [MyPham] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [MyPham] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [MyPham] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [MyPham] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [MyPham] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [MyPham] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [MyPham] SET RECOVERY SIMPLE 
GO
ALTER DATABASE [MyPham] SET  MULTI_USER 
GO
ALTER DATABASE [MyPham] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [MyPham] SET DB_CHAINING OFF 
GO
ALTER DATABASE [MyPham] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [MyPham] SET TARGET_RECOVERY_TIME = 0 SECONDS 
GO
USE [MyPham]
GO
/****** Object:  Table [dbo].[BanBe]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[BanBe](
	[MaBB] [int] IDENTITY(1,1) NOT NULL,
	[MaKH] [nvarchar](50) NULL,
	[MaSP] [int] NULL,
	[HoTen] [nvarchar](50) NULL,
	[Email] [nvarchar](50) NULL,
	[NgayGui] [datetime] NULL,
	[GhiChu] [nchar](10) NULL,
 CONSTRAINT [PK_BanBe] PRIMARY KEY CLUSTERED 
(
	[MaBB] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[BinhLuan]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[BinhLuan](
	[MaBL] [int] IDENTITY(1,1) NOT NULL,
	[MaSP] [int] NULL,
	[MaKH] [nvarchar](50) NULL,
	[NgayBL] [datetime] NULL,
	[HoTen] [nvarchar](50) NULL,
	[Email] [nvarchar](50) NULL,
	[NoiDung] [nvarchar](max) NULL,
 CONSTRAINT [PK_BinhLuan] PRIMARY KEY CLUSTERED 
(
	[MaBL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Blog]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Blog](
	[MaBlog] [int] IDENTITY(1,1) NOT NULL,
	[TenBlog] [nvarchar](50) NULL,
	[NoiDung] [nvarchar](max) NULL,
	[NgayDang] [datetime] NULL,
	[MaLoaiBlog] [int] NULL,
 CONSTRAINT [PK_Blog] PRIMARY KEY CLUSTERED 
(
	[MaBlog] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[ChiTietHD]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ChiTietHD](
	[MaCT] [int] IDENTITY(0,1) NOT NULL,
	[MaHD] [int] NULL,
	[MaSP] [int] NULL,
	[DonGia] [float] NULL,
	[SoLuong] [int] NULL,
	[GiamGia] [float] NULL,
 CONSTRAINT [PK_ChiTietHD] PRIMARY KEY CLUSTERED 
(
	[MaCT] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[ChuDe]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ChuDe](
	[MaCD] [int] IDENTITY(1,1) NOT NULL,
	[TenCD] [nvarchar](50) NULL,
	[MaNV] [nvarchar](50) NULL,
 CONSTRAINT [PK_ChuDe] PRIMARY KEY CLUSTERED 
(
	[MaCD] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[HoaDon]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HoaDon](
	[MaHD] [int] IDENTITY(1,1) NOT NULL,
	[MaKH] [nvarchar](50) NULL,
	[NgayDat] [datetime] NULL,
	[NgayGiao] [datetime] NULL,
	[MaNV] [nvarchar](50) NULL,
	[HoTen] [nvarchar](50) NULL,
	[DiaChi] [nvarchar](50) NOT NULL,
	[CachThanhToan] [nvarchar](50) NULL,
	[CachVanChuyen] [nvarchar](50) NULL,
	[PhiVanChuyen] [float] NULL,
	[MaTrangThai] [int] NULL,
	[GhiChu] [nvarchar](50) NULL,
	[DienThoai] [nvarchar](50) NULL,
	[TenNgNhan] [nvarchar](50) NULL,
	[DTNgNhan] [nvarchar](50) NULL,
	[DiaChiNgNhan] [nvarchar](50) NULL,
	[TongTien] [float] NULL,
 CONSTRAINT [PK_HoaDon] PRIMARY KEY CLUSTERED 
(
	[MaHD] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[HoiDap]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HoiDap](
	[MaHDap] [int] NOT NULL,
	[CauHoi] [nvarchar](50) NULL,
	[TraLoi] [nvarchar](50) NULL,
	[NgayDua] [datetime] NULL,
	[MaNV] [nvarchar](50) NULL,
 CONSTRAINT [PK_HoiDap] PRIMARY KEY CLUSTERED 
(
	[MaHDap] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[KhachHang]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[KhachHang](
	[MaKH] [nvarchar](50) NOT NULL,
	[MatKhau] [nvarchar](100) NULL,
	[HoTen] [nvarchar](50) NULL,
	[GioiTinh] [bit] NULL,
	[NgaySinh] [date] NULL,
	[DiaChi] [nvarchar](50) NULL,
	[DienThoai] [nvarchar](50) NULL,
	[Email] [nvarchar](50) NULL,
	[HieuLuc] [bit] NULL,
	[VaiTro] [int] NULL,
	[RandomKey] [varchar](50) NULL,
 CONSTRAINT [PK_KhachHang] PRIMARY KEY CLUSTERED 
(
	[MaKH] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[KhoHang]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[KhoHang](
	[MaKho] [int] IDENTITY(1,1) NOT NULL,
	[MaSP] [int] NULL,
	[SoLuong] [int] NULL,
 CONSTRAINT [PK_KhoHang] PRIMARY KEY CLUSTERED 
(
	[MaKho] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[KhuyenMai]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[KhuyenMai](
	[MaKM] [int] IDENTITY(1,1) NOT NULL,
	[codeKM] [nvarchar](50) NULL,
	[LoaiKM] [nvarchar](50) NULL,
	[MaKH] [nvarchar](50) NULL,
 CONSTRAINT [PK_KhuyenMai] PRIMARY KEY CLUSTERED 
(
	[MaKM] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[LienHe]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LienHe](
	[MaGY] [int] IDENTITY(1,1) NOT NULL,
	[TieuDe] [nvarchar](max) NULL,
	[NoiDung] [nvarchar](max) NULL,
	[NgayGY] [datetime] NULL,
	[HoTen] [nvarchar](50) NULL,
	[Email] [nvarchar](50) NULL,
	[DienThoai] [nvarchar](50) NULL,
 CONSTRAINT [PK_LienHe] PRIMARY KEY CLUSTERED 
(
	[MaGY] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[Loai]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Loai](
	[MaLoai] [int] IDENTITY(1,1) NOT NULL,
	[TenLoai] [nvarchar](50) NULL,
	[TenLoaiAlias] [nvarchar](50) NULL,
	[MoTa] [nvarchar](max) NULL,
 CONSTRAINT [PK_Loai] PRIMARY KEY CLUSTERED 
(
	[MaLoai] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[LoaiBlog]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LoaiBlog](
	[MaLoaiBlog] [int] IDENTITY(1,1) NOT NULL,
	[TenLoaiBlog] [nvarchar](max) NULL,
	[MoTa] [nvarchar](50) NULL,
 CONSTRAINT [PK_LoaiBlog] PRIMARY KEY CLUSTERED 
(
	[MaLoaiBlog] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[NhaCungCap]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[NhaCungCap](
	[MaNCC] [nvarchar](50) NOT NULL,
	[TenCongTy] [nvarchar](50) NULL,
	[Logo] [nvarchar](50) NULL,
	[Email] [nvarchar](50) NULL,
	[DienThoai] [nvarchar](50) NULL,
	[DiaChi] [nvarchar](50) NULL,
	[MoTa] [nvarchar](max) NULL,
 CONSTRAINT [PK_NhaCungCap] PRIMARY KEY CLUSTERED 
(
	[MaNCC] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[NhanVien]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[NhanVien](
	[MaNV] [nvarchar](50) NOT NULL,
	[HoTen] [nvarchar](50) NULL,
	[Email] [nvarchar](50) NULL,
	[MatKhau] [nvarchar](50) NULL,
 CONSTRAINT [PK_NhanVien] PRIMARY KEY CLUSTERED 
(
	[MaNV] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[PhanCong]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[PhanCong](
	[MaPC] [int] IDENTITY(1,1) NOT NULL,
	[MaNV] [nvarchar](50) NULL,
	[MaPB] [varchar](7) NULL,
	[NgayPC] [datetime] NULL,
	[HieuLuc] [bit] NULL,
 CONSTRAINT [PK_PhanCong] PRIMARY KEY CLUSTERED 
(
	[MaPC] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[PhanQuyen]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[PhanQuyen](
	[MaPQ] [int] IDENTITY(1,1) NOT NULL,
	[MaPB] [varchar](7) NULL,
	[MaTrang] [int] NULL,
	[Them] [bit] NULL,
	[Sua] [bit] NULL,
	[Xoa] [bit] NULL,
	[Xem] [bit] NULL,
 CONSTRAINT [PK_PhanQuyen] PRIMARY KEY CLUSTERED 
(
	[MaPQ] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[PhongBan]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[PhongBan](
	[MaPB] [varchar](7) NOT NULL,
	[TenPB] [nvarchar](50) NULL,
	[ThongTin] [nvarchar](max) NULL,
 CONSTRAINT [PK_PhongBan] PRIMARY KEY CLUSTERED 
(
	[MaPB] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[SanPham]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SanPham](
	[MaSP] [int] IDENTITY(1,1) NOT NULL,
	[MaHieu] [int] NULL,
	[TenSP] [nvarchar](50) NULL,
	[TenAlias] [nvarchar](50) NULL,
	[MaLoai] [int] NULL,
	[MoTa] [nvarchar](max) NULL,
	[DonGia] [float] NULL,
	[Hinh] [nvarchar](50) NULL,
	[Hinh2] [nvarchar](50) NULL,
	[GiaCu] [float] NULL,
	[MaNCC] [nvarchar](50) NULL,
	[SpHot] [bit] NULL,
 CONSTRAINT [PK_SanPham] PRIMARY KEY CLUSTERED 
(
	[MaSP] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
/****** Object:  Table [dbo].[ThuongHieu]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ThuongHieu](
	[MaHieu] [int] IDENTITY(1,1) NOT NULL,
	[TenHieu] [nvarchar](50) NULL,
	[Hinh] [nvarchar](50) NULL,
 CONSTRAINT [PK_ThuongHieu] PRIMARY KEY CLUSTERED 
(
	[MaHieu] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[TrangThai]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TrangThai](
	[MaTrangThai] [int] NOT NULL,
	[TenTrangThai] [nvarchar](50) NULL,
	[MoTa] [nvarchar](50) NULL,
 CONSTRAINT [PK_TrangThai] PRIMARY KEY CLUSTERED 
(
	[MaTrangThai] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[TrangWeb]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TrangWeb](
	[MaTrang] [int] IDENTITY(1,1) NOT NULL,
	[TenTrang] [nvarchar](50) NULL,
	[URL] [nvarchar](250) NULL,
 CONSTRAINT [PK_TrangWeb] PRIMARY KEY CLUSTERED 
(
	[MaTrang] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
/****** Object:  Table [dbo].[YeuThich]    Script Date: 12/21/18 9:27:14 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[YeuThich](
	[MaYT] [int] IDENTITY(1,1) NOT NULL,
	[MaSP] [int] NULL,
	[MaKH] [nvarchar](50) NULL,
	[NgayChon] [datetime] NULL,
	[MoTa] [nvarchar](50) NULL,
 CONSTRAINT [PK_YeuThich] PRIMARY KEY CLUSTERED 
(
	[MaYT] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

GO
SET IDENTITY_INSERT [dbo].[BinhLuan] ON 

INSERT [dbo].[BinhLuan] ([MaBL], [MaSP], [MaKH], [NgayBL], [HoTen], [Email], [NoiDung]) VALUES (5, 3, N'dung', CAST(0x0000A9BC00DD1EE9 AS DateTime), N'Bùi Phương Dung', N'dung', N' ahihi')
INSERT [dbo].[BinhLuan] ([MaBL], [MaSP], [MaKH], [NgayBL], [HoTen], [Email], [NoiDung]) VALUES (6, 4, N'dung', CAST(0x0000A9BC00DDB286 AS DateTime), N'Bùi Phương Dung', N'dung', N'Hàng dỏm ')
INSERT [dbo].[BinhLuan] ([MaBL], [MaSP], [MaKH], [NgayBL], [HoTen], [Email], [NoiDung]) VALUES (7, 5, N'dung', CAST(0x0000A9BC00DE42F6 AS DateTime), N'Bùi Phương Dung', N'dung', N'Đẹp')
INSERT [dbo].[BinhLuan] ([MaBL], [MaSP], [MaKH], [NgayBL], [HoTen], [Email], [NoiDung]) VALUES (10, 24, N'leeminho', CAST(0x0000A9BD00E59D84 AS DateTime), N'Lee Min Ho', N'lee@gmail.com', N' ok')
INSERT [dbo].[BinhLuan] ([MaBL], [MaSP], [MaKH], [NgayBL], [HoTen], [Email], [NoiDung]) VALUES (11, 7, N'leeminho', CAST(0x0000A9BD00E5A8A3 AS DateTime), N'Lee Min Ho', N'lee@gmail.com', N' k')
SET IDENTITY_INSERT [dbo].[BinhLuan] OFF
SET IDENTITY_INSERT [dbo].[ChiTietHD] ON 

INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (3, 10, 15, 5200000, 1, NULL)
INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (4, 11, 13, 630000, 1, NULL)
INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (5, 11, 4, 129000, 1, NULL)
INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (6, 11, 6, 630000, 1, NULL)
INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (7, 12, 14, 110000, 1, NULL)
INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (8, 13, 15, 5200000, 6, NULL)
INSERT [dbo].[ChiTietHD] ([MaCT], [MaHD], [MaSP], [DonGia], [SoLuong], [GiamGia]) VALUES (9, 14, 15, 5200000, 2, NULL)
SET IDENTITY_INSERT [dbo].[ChiTietHD] OFF
SET IDENTITY_INSERT [dbo].[HoaDon] ON 

INSERT [dbo].[HoaDon] ([MaHD], [MaKH], [NgayDat], [NgayGiao], [MaNV], [HoTen], [DiaChi], [CachThanhToan], [CachVanChuyen], [PhiVanChuyen], [MaTrangThai], [GhiChu], [DienThoai], [TenNgNhan], [DTNgNhan], [DiaChiNgNhan], [TongTien]) VALUES (10, N'dung', CAST(0x0000A9B601322ECE AS DateTime), NULL, NULL, N'Bùi Phương Dung', N'TPHCM', NULL, NULL, 0, 3, NULL, NULL, NULL, NULL, NULL, NULL)
INSERT [dbo].[HoaDon] ([MaHD], [MaKH], [NgayDat], [NgayGiao], [MaNV], [HoTen], [DiaChi], [CachThanhToan], [CachVanChuyen], [PhiVanChuyen], [MaTrangThai], [GhiChu], [DienThoai], [TenNgNhan], [DTNgNhan], [DiaChiNgNhan], [TongTien]) VALUES (11, N'dung', CAST(0x0000A9B601328CBF AS DateTime), NULL, NULL, N'Bùi Phương Dung', N'TPHCM', NULL, NULL, 0, 3, NULL, NULL, NULL, NULL, NULL, NULL)
INSERT [dbo].[HoaDon] ([MaHD], [MaKH], [NgayDat], [NgayGiao], [MaNV], [HoTen], [DiaChi], [CachThanhToan], [CachVanChuyen], [PhiVanChuyen], [MaTrangThai], [GhiChu], [DienThoai], [TenNgNhan], [DTNgNhan], [DiaChiNgNhan], [TongTien]) VALUES (12, N'dung', CAST(0x0000A9B601334F38 AS DateTime), NULL, NULL, N'Bùi Phương Dung', N'TPHCM', NULL, NULL, 0, 3, NULL, NULL, NULL, NULL, NULL, NULL)
INSERT [dbo].[HoaDon] ([MaHD], [MaKH], [NgayDat], [NgayGiao], [MaNV], [HoTen], [DiaChi], [CachThanhToan], [CachVanChuyen], [PhiVanChuyen], [MaTrangThai], [GhiChu], [DienThoai], [TenNgNhan], [DTNgNhan], [DiaChiNgNhan], [TongTien]) VALUES (13, N'dung', CAST(0x0000A9B601355A4B AS DateTime), NULL, NULL, N'Bùi Phương Dung', N'TPHCM', NULL, NULL, 0, 1, NULL, NULL, NULL, NULL, NULL, NULL)
INSERT [dbo].[HoaDon] ([MaHD], [MaKH], [NgayDat], [NgayGiao], [MaNV], [HoTen], [DiaChi], [CachThanhToan], [CachVanChuyen], [PhiVanChuyen], [MaTrangThai], [GhiChu], [DienThoai], [TenNgNhan], [DTNgNhan], [DiaChiNgNhan], [TongTien]) VALUES (14, N'dung', CAST(0x0000A9B601364DDD AS DateTime), NULL, NULL, N'Bùi Phương Dung', N'TPHCM', NULL, NULL, 0, 2, NULL, NULL, NULL, NULL, NULL, NULL)
SET IDENTITY_INSERT [dbo].[HoaDon] OFF
INSERT [dbo].[KhachHang] ([MaKH], [MatKhau], [HoTen], [GioiTinh], [NgaySinh], [DiaChi], [DienThoai], [Email], [HieuLuc], [VaiTro], [RandomKey]) VALUES (N'bao', N'bao', N'Châu Thái Bảo', 1, CAST(0x86220B00 AS Date), N'TPHCM', N'12356789', N'bao@gmail.com', 0, NULL, NULL)
INSERT [dbo].[KhachHang] ([MaKH], [MatKhau], [HoTen], [GioiTinh], [NgaySinh], [DiaChi], [DienThoai], [Email], [HieuLuc], [VaiTro], [RandomKey]) VALUES (N'dung', N'dung', N'Bùi Phương Dung', 0, CAST(0x1D200B00 AS Date), N'TPHCM', N'123456789', N'dung@gmail.com', 0, 0, NULL)
INSERT [dbo].[KhachHang] ([MaKH], [MatKhau], [HoTen], [GioiTinh], [NgaySinh], [DiaChi], [DienThoai], [Email], [HieuLuc], [VaiTro], [RandomKey]) VALUES (N'leeminho', N'lee', N'Lee Min Ho', 1, CAST(0xEB150B00 AS Date), N'TPHCM', N'896798261', N'lee@gmail.com', 0, NULL, NULL)
INSERT [dbo].[KhachHang] ([MaKH], [MatKhau], [HoTen], [GioiTinh], [NgaySinh], [DiaChi], [DienThoai], [Email], [HieuLuc], [VaiTro], [RandomKey]) VALUES (N'trang', N'trang', N'Võ Quỳnh Mai Trang', 0, CAST(0x7A200B00 AS Date), N'Bến Tre', N'12345', N'trang@gmail.com', 0, NULL, NULL)
SET IDENTITY_INSERT [dbo].[KhoHang] ON 

INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (1, 1, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (2, 2, 97)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (3, 3, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (4, 4, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (5, 5, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (6, 6, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (7, 7, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (8, 8, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (9, 9, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (10, 10, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (11, 11, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (12, 12, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (13, 13, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (14, 14, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (15, 15, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (16, 16, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (17, 17, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (18, 18, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (19, 19, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (20, 20, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (21, 21, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (22, 22, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (23, 23, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (24, 24, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (39, 31, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (40, 32, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (41, 33, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (42, 35, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (43, 36, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (44, 37, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (45, 38, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (46, 39, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (47, 40, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (50, 43, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (53, 46, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (56, 49, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (58, 51, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (59, 52, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (61, 54, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (62, 55, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (63, 56, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (64, 57, 100)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (65, 58, 0)
INSERT [dbo].[KhoHang] ([MaKho], [MaSP], [SoLuong]) VALUES (66, 59, 100)
SET IDENTITY_INSERT [dbo].[KhoHang] OFF
SET IDENTITY_INSERT [dbo].[LienHe] ON 

INSERT [dbo].[LienHe] ([MaGY], [TieuDe], [NoiDung], [NgayGY], [HoTen], [Email], [DienThoai]) VALUES (1, N's', N's', CAST(0x0000A9BB00023D94 AS DateTime), N'a', N's', N's')
SET IDENTITY_INSERT [dbo].[LienHe] OFF
SET IDENTITY_INSERT [dbo].[Loai] ON 

INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (1, N'BB/CC/DD Cushion', N'bb-cc-dd', N'0')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (2, N'Phấn phủ', N'phan-phu', N'0')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (7, N'Son môi', N'son-moi', N'0')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (8, N'Dưỡng môi', N'duong-moi', N'0')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (11, N'Dưỡng body', N'duong-body', N'1')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (12, N'Dưỡng tay', N'duong-tay', N'1')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (13, N'Dưỡng mặt', N'duong-mat', N'1')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (14, N'Sữa rửa mặt', N'sua-rua-mat', N'1')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (15, N'Tẩy Trang', N'tay-trang', N'1')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (16, N'Mascara', N'mascara', N'0')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (17, N'Kẻ mắt', N'ke-mat', N'0')
INSERT [dbo].[Loai] ([MaLoai], [TenLoai], [TenLoaiAlias], [MoTa]) VALUES (18, N'Kẻ lông mày', N'ke-may', N'0')
SET IDENTITY_INSERT [dbo].[Loai] OFF
SET IDENTITY_INSERT [dbo].[LoaiBlog] ON 

INSERT [dbo].[LoaiBlog] ([MaLoaiBlog], [TenLoaiBlog], [MoTa]) VALUES (1, N'Review mỹ phẩm ', N'2')
INSERT [dbo].[LoaiBlog] ([MaLoaiBlog], [TenLoaiBlog], [MoTa]) VALUES (2, N'Makeup', N'2')
INSERT [dbo].[LoaiBlog] ([MaLoaiBlog], [TenLoaiBlog], [MoTa]) VALUES (3, N'Skincare', N'2')
INSERT [dbo].[LoaiBlog] ([MaLoaiBlog], [TenLoaiBlog], [MoTa]) VALUES (4, N'ChangMakeup', N'3')
INSERT [dbo].[LoaiBlog] ([MaLoaiBlog], [TenLoaiBlog], [MoTa]) VALUES (5, N'CIn CIty', N'3')
INSERT [dbo].[LoaiBlog] ([MaLoaiBlog], [TenLoaiBlog], [MoTa]) VALUES (6, N'Chlole', N'3')
SET IDENTITY_INSERT [dbo].[LoaiBlog] OFF
INSERT [dbo].[NhanVien] ([MaNV], [HoTen], [Email], [MatKhau]) VALUES (N'1', N'Dung', N'dung', N'123')
SET IDENTITY_INSERT [dbo].[SanPham] ON 

INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (1, 1, N'Phấn phủ nén Water Supreme Laneige ', NULL, 1, N'Laneige Water Supreme Finishing Pact SPF 25PA++ thuộc dòng sản phẩm Water Supreme Laneige của Laneige, chứa các hoạt chất dưỡng ẩm, mang lại một lớp "trang điểm sáng mịn và rạng ngời," khiến cho da trở nên mềm mại như da em bé.', 590000, N'phanphunenLaneige.png', N'phanphunenLaneige1.png', 630000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (2, 1, N'Phấn nước Lacôme Teint Idole Ultra Cushion', NULL, 1, N'Chất kem lỏng, siêu nhẹ, dễ tán cho lớp nền mỏng tự nhiên và dù bạn tăng độ che phủ nhiều hơn bằng cách dặm nhiều lớp kem nhưng vẫn cảm giác nhẹ tênh như không – không hề gây nặng mặt, khó chịu.
Làn da của bạn sẽ bừng sáng ngay tức thì nhờ lớp finish dạng matte, khuôn mặt bạn sẽ trông đầy sức sống theo cách rất tự nhiên.', 129900, N'phannuoclacome.jpg', N'phannuoclacome1.jpg', 150000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (3, 2, N'Phấn Nước Cushion Amok Lovefit', NULL, 1, N'Lovefit Cushion là sản phẩm phấn nước từ hãng mỹ phẩm nổi tiếng Hàn Quốc, với kết cấu hạt phấn tự tan và cấu trúc tự khô, cho bạn lớp make up hoàn hảo, và vô cùng tự nhiên trong thời gian ngắn. Amok Lovefit Cushion chứa ưu điểm vượt trội trong kiềm dầu và điều tiết bã nhờn, tuy nhiên lại tạo lớp nền căng mịn, cảm giác như da được uống nước.', 259000, N'phannuoccushion.jpg', N'phannuoccushion1.jpg', 280000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (4, 2, N'Phấn phủ Innisfree No-Sebum Mineral Powder', NULL, 1, N'Thiết kế bên ngoài của phấn phủ kiềm dầu Innisfree No-Sebum Mineral Powder rất đơn giản và xinh xắn. Sản phẩm là một chiếc hộp nhỏ, trọng lượng 5g, nắp vặn tròn, màu xanh pastel rất hợp thời trang. Bên trong có bông phấn đi kèm và bột phấn trắng tinh.', 129000, N'phanphukiemdau.jpg', N'phanphukiemdau1.jpg', 150000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (5, 3, N'Missha Magic Cushion Moisture SPF 50+', NULL, 2, N'Phấn nước Missha Minions Magic Cushion Cover SPF50+ PA+++– phiên bản Minions đặc biệt kèm theo 1 lõi thay thế và 1 bông phấn!', 290000, N'misshacushion.jpg', N'misshacushion1.jpg', 310000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (6, 3, N'Phấn phủ Make Up Forever Shine On Powder', NULL, 2, N'Phấn phủ là bước cuối cùng trong việc trang điểm nhưng vô cùng quan trong bởi lớp phấn mỏng mịn giúp làn da thêm mịn màng, bảo vệ lớp trang điểm lâu phai, không bị bóng dầu.', 630000, N'phanphumake.png', N'phanphumake.jpg', 650000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (7, 4, N'BB cream M30 oil free the face shop', NULL, 1, N'Clean face Oil control BB Cream có tác dụng giúp kiềm dầu, kiểm soát độ nhờn của da hiệu quả. Vì thế bạn hoàn toàn yên tâm vì nếu có sở hữu làn da nhờn thì đã có trợ thủ trang điểm đắc lực bên cạnh giúp che khuyết điểm như nếp nhăn, mụn, lỗ chân lông', 249000, N'bbcream.jpg', N'bbcream1.jpg', 260000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (8, 4, N'Phấn Holika Holika Water Drop CC Pact', NULL, 2, N'Phấn CC Holika Holika Water Drop CC Pact SPF50+ PA+++ chứa đựng đầy đủ mọi tính năng và ưu điểm của phấn kem: tạo lớp nền che phủ mỏng mịn, trong suốt siêu khô thoáng, và đương nhiên nó "ăn đứt" phấn dạng bột, thậm chí còn có khả năng che phủ tốt hơn hẳn những dòng phấn phủ thông thường khác.

Hơn nữa nó còn được dùng như một dạng phấn đa công dụng trong một sản phẩm, bạn có thể thay thế hầu hết các bước trang điểm truyền thống như kem lót, kem nền, phấn phủ… và cả kem che khuyết điểm với khả năng bao phủ tối đa và hoàn hảo vô cùng.', 329000, N'phan6.jpg', N'phan61.jpg', 350000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (9, 5, N'Kem nền Burberry Cashmere Flawless Soft', NULL, 1, N'Kem nền Burberry Cashmere Flawless Soft -Matte Foundation là 1 trong những dòng kem nền đầu tiên hãng cho ra mắt, hướng đến xu hướng trang điểm nhẹ nhàng tự nhiên với độ che phủ mỏng hơn, dưỡng ẩm tốt hơn, làn da bóng khỏe hơn nhưng vẫn bảo đảm nét thanh lịch và sang trọng.

Cảm giác khi apply lên da là không nặng mặt, không gây cảm giác bí da, đặc biệt 1 điều em này càng dùng thì càng thấy nhẹ mặt hơn nha. Vì tính chất không quá dày và ẩm trên da nên người dùng sẽ không thấy khó chịu với thời tiết oi bức như thế này.', 1410000, N'phan5.png', N'phan51.jpg', 1500000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (10, 5, N'Phấn Nước The Face Shop CC Ultra Moist Cushion', NULL, 1, N'Là kem trang điểm dưỡng da, làm đều màu da, thu nhỏ lỗ chân lông, mờ sẹo, che khuyết điểm, làn da trở nên mịn màng, tươi sáng.

Thích hợp cho da khô, da bong tróc, da nhạy cảm, da sần, da thô nhám, da lổ chân lông to, da nhiều mụn đầu đen.Bổ sung tinh chất dưỡng ẩm và làm sáng da, cùng hỗn hợp vitamin giúp duy trì da khỏe mạnh đàn hồi và láng mịn trong thời gian dài lâu. Lớp kem CC được đẩy lên qua hàng ngàn lỗ ti li qua bông mút, tạo lớp nền giàu oxi và thật mỏng mịn sảng khoải khi sử dụng lên da.

Chống nắng SPF 50+ PA+++ giúp da tránh khỏi các tác hại của tia cực tím, da sẽ được bảo vệ an toàn suốt cả ngày mà không lo đen sạm.', 320000, N'phan1.png', N'phan12.jpg', 345000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (11, 6, N'Phấn má hồng W7 Candy Blush (6g)', NULL, 1, N'Phấn má hồng là sự kết hợp giữa ánh ngọc trai và màu sắc rực rỡ cho đôi má bạn đỏ hồng dễ thương rất tự nhiên
Hôp xinh xắn, kèm gương, thiết kế nhỏ gọn để trong túi xách thật tiện mà không sợ bị vỡ ra như các loại phấn má phủ thông thường
', 99000, N'phanmahong.jpg', N'phanmahong1.jpg', 120000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (12, 6, N'Son dưỡng 3CE Tint Treatment Lip Balm', NULL, 8, N'3CE là thương hiệu mỹ phẩm Hàn Quốc mới ra đời năm 2009 dưới sự sáng lập của công ty thời trang trực tuyến hàng đầu Hàn Quốc – Stylenanda. Nhãn hàng 3 Concepts Eyes tập trung thu hút khách hàng bằng các loại son như matte, tint, … với bảng màu sáng tạo và cả cách sử dụng cũng rất mới lạ.', 349000, N'son3ce.jpg', N'son3ce1.jpg', 370000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (13, 7, N'Son Dưỡng Môi Dior Addict Lip Glow (3.5g)', NULL, 8, N'Thương hiệu Dior là thương hiệu thời trang mỹ phẩm do nhà thiết kế lừng danh Christian Dior thành lập, chuyên thiết kế và tạo ra những bộ sưu tập đắt đỏ nhất thế giới. Son môi Dior luôn là lựa chọn hàng đầu của phái đẹp, bên cạnh những dòng son nổi như cồn như Rouge Dior hay Diorific thì dòng son Dior Addict Lip Glow - dòng son dưỡng có màu cũng chính là nàng thơ được ao ước, mong mỏi kiếm tìm khắp nơi.', 630000, N'sonduongdior.png', N'sonduongdior1.jpg', 650000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (14, 7, N'Son Bóng Có màu Ulta Butter Balm Lip Gloss', NULL, 8, N'Chứa nhiều dưỡng chất giúp môi luôn căng bóng, mịn màng và ửng hồng tự nhiên

Kết cấu mềm mại, nhẹ nhàng không gây bết dính như son bóng thường khi thoa lên môi giúp môi luồn căng mọng đầy sức sống

Màu son trẻ trung, hiện đại, phù hợp mọi lứa tuổi và nhiều phong cách trang điểm khác nhau', 110000, N'son9.jpg', N'son91.jpg', 135000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (15, 8, N'Set 12 son Kylie Holiday Edition Matte Liquid', NULL, 8, N'Dòng son từ hot-girl nổi tiếng Kylie Jenner, liên tục cháy hàng vì quá hot, bên cạnh màu son đẹp, độc, lạ và vẻ ngoài hết sức sang chảnh, còn có chất lượng son vô cùng mịn mà chứa nhiều dưỡng chất nên dù là son kem lì vẫn không gây khô môi hay bong vảy, giúp bạn tự tin làm việc hay đi chơi nhiều giờ liền mà không sợ bay màu.

Kết cấu mềm mại, nhẹ nhàng không gây bết dính khi thoa lên môi giúp môi luồn căng mọng đầy sức sống

Màu son trẻ trung, hiện đại, phù hợp mọi lứa tuổi và nhiều phong cách trang điểm khác nhau', 5200000, N'sonduong5.jpg', N'sonduong51.jpg', 5350000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (16, 8, N'Son L’oreal Tint Caresse Lip Tint 3c', NULL, 7, N'Về thiết kế, ngoài đầu mút son được làm dạng cushion hình trái tim, son cũng sở hữu thiết kế nổi bật ‘bóng loáng’ với vỏ son bằng kim loại chắc chắn, trông phát là yêu :3 Dùng son này, bạn không phải lo chảy son hoặc gẫy đầu son. Rất tiện lợi.', 190000, N'sonloreal.jpg', N'sonloreal1.jpg', 200000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (17, 9, N'Tarte Rainforest of the Sea™ Quench', NULL, 7, N'Tarte được biết đến là thương hiệu mỹ phẩm cao cấp có tiếng trên thị trường vì được nhiều chuyên gia trang điểm danh tiếng tin dùng Tuy nhiên Ai cũng biết giá thành của em này khá cao nên nhiều người cũng còn đắn đo trước khi quyết định đến em về.', 350000, N'sontarte.jpg', N'sontarte1.jpg', 390000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (18, 9, N'Set son Bút chì 3CE Drawing Lip Pen', NULL, 7, N'Về phần cây son nhìn y hệt cây viết chì màu, tuy nhiên hãng thiết kế hơi ngắn, mình thích hơi dài hơn chút xíu nhìn cho nó đồng thanh, đồng thủ hơn. Không phải chất son ít mà mình chê, nhưng mình cảm giác cây son nó lùn lùn sao ah, chưa được thuận mắt. Với thiết kế dạng viết chì đầu son nhỏ giúp mình tán đều, đẹp và che sạch các khuyết điểm của viền môi, đặc biệt là môi thâm.', 1490000, N'setson3ce.jpg', N'setson3ce1.jpg', 1650000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (19, 10, N'Son thỏi lì Agapan Matte Lipstick', NULL, 7, N'Son Agapan Matte Lipstick - Kế thừa những ưu điểm của dòng son kem lì đình đám Agapan, chắc chắn dòng son thỏi Agapan Matte Lipstick sẽ chinh phục các nàng mê so bởi chất son siêu đẹp.

Đầu tiên là về ngoại hình, với thiết kế vuông vức không cầu lì hoa mỹ, đơn giản với tông đen chủ đạo hoàn toàn hợp với những bạn yêu sự đơn giản tinh tế. Khả năng giử màu chuẩn của 1 cây son lì, lên đến 5,6 tiếng.', 160000, N'son3.jpg', N'son31.jpg', 185000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (20, 10, N'Son Thỏi Burberry Kisses Hydrating Lip Colour', NULL, 7, N'Thiết kế sang trọng, sọc caro đặc trưng của Burberry, son có mùi thơm nước hoa, thoa lên môi khoảng 30 phút thì mất mùi

Chất son nhẹ, lên màu chuẩn không bị nặng môi, cấp ẩm tối ưu, không lo khô môi dù làm việc cả ngày

Thương hiệu Burberry cao cấp hàng đầu thế giới, chú trọng về vẻ ngoài lẫn chất lượng bên trong, là một cây son đẳng cấp mà giới thượng lưu yêu thích', 850000, N'son8.jpg', N'son81.jpg', 120000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (21, 11, N'Son Agapan Vita Lip Stain', NULL, 7, N'Agapan đã không còn mấy xa lạ đối với các tín đồ làm đep trên toàn Châu Á. Các dòng son của Agapan đáp ứng được yêu cầu về màu sắc, chất son và luôn làm hài lòng các tín đồ mê son kể cả những cô nàng khó tính nhất. Đầu tháng 8 năm nay, thương hiệu Agapan đã cho ra đời phiên bản son kem lì Agapan Vita Lip Stain với kích thước nhỏ nhắn, dễ thương và trông chẳng khác nào một cây son thỏi.

Chất son mỏng mịn nhưng vẫn lấp đầy các rãnh trên môi và che phủ nếp nhăn một cách hoàn hảo, chỉ với lớp mỏng bạn đã có được đôi môi chuẩn màu mà không bị lộ khuyết điểm. Thành phần son cải tiến hơn với công thức chiết xuất từ các loại trái cây', 129000, N'sonapaga.png', N'sonapaga1.jpg', 140000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (22, 11, N'Set Son Holiday Special Joyful Mini Lipstick Kit', NULL, 7, N'Holiday Special Joyful Mini Lipstick Kit là bộ son mini, mỗi phiên bản gồm 3 màu son siêu đẹp được cân đo đong đếm sao cho thật phù hợp với không khí rộn ràng cuối năm. Màu sắc chủ đạo được dùng trong thiết kế lần này là những tông đen, trắng, vàng kim vừa sang trọng vừa làm nổi bật được không khí lễ hội an lành. Những chấm vàng gợi nhớ đến những ánh đèn lấp lánh trong đêm Noel, nên có thể nói thiết kế của hai kit son này rất đẹp cho một món quà tặng.

Chất son của The Face Shop luôn đặt yêu cầu mềm mịn, mướt môi và màu lên chuẩn, sẵn sàng đồng hành với các cô gái thân yêu dù trong những ngày gió lạnh giá buốt.', 320000, N'son4.jpg', N'son41.jpg', 350000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (23, 12, N'Sữa Dưỡng Thể Bath & Body Works - Dark Kiss', NULL, 11, N'Sữa dưỡng thể Bath & Body Works - Dark Kiss với công thức dưỡng da ưu việt như bơ hạt mỡ, tinh dầu jojoba, vitamin E giúp bảo vệ, nuôi dưỡng, cung cấp dưỡng chất và độ ẩm cho làn da suốt cả ngày. Công thức không dầu nhờn thấm nhanh vào da, giúp da hấp thụ một cách nhanh chóng, cho bạn làn da mềm mại, mịn màng, không gây cảm giác rít dính cùng hương thơm tinh tế, sang trọng, quyến rũ lưu lại trên da.', 195000, N'duongbody11.png', N'duongbody12.jpg', 210000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (24, 12, N'Sữa Dưỡng Thể Vaseline Intensive Care Aloe Soothe', NULL, 11, N'Vaseline Aloe Soothe (màu xanh) làm mềm mượt và mát da do có chiết xuất từ cây lô hội, hấp thụ vào da một cách nhanh chóng để cung cấp độ ẩm, làm sạch da mà không bị bết dính, Vòi bơm giúp bạn tiết kiệm lượng sữa dưỡng thể mỗi khi sử dụng', 135000, N'duongbody21.png', N'duongbody22.jpg', 159000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (31, 13, N'Dưỡng Thể Vaseline Intensive Care Advanced Repair', NULL, 11, N'Sữa dưỡng thể trắng da Vaseline Intensive Advanced Repair dược chiết xuất từ thiên nhiên có độ ẩm gấp 3 lần so với dưỡng thể thông thường, giúp làn da khô ráp trở nên mềm mịn hơn', 135000, N'duongbody31.png', N'duongbody32.jpg', 150000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (32, 14, N'Dưỡng Thể St.Ives Hydrating Vitamin E & Avocado', NULL, 11, N'Sữa dưỡng da toàn thân chứa Vitamin E và dầu dưỡng chiết xuất từ quả bơ xanh giúp bổ sung độ ẩm, cho làn da mềm mịn và khỏe mạnh.', 140000, N'duongbody41.jpg', N'duongbody42.png', 150000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (33, 15, N'Sữa Dưỡng Thể Vaseline Healthy White UV Lightening', NULL, 11, N'Lotion dưỡng thể Vaseline Healthy White Lightening (màu hồng) chính là một giải pháp toàn diện và hiệu quả giúp dưỡng trắng sáng làn da của bạn hàng ngày.', 135000, N'duongbody51.png', N'duongbody52.png', 150000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (35, 15, N'Dưỡng Thể Vaseline Total Moisture Cocoa', NULL, 11, N'Xuất xứ: Ấn Độ Quy cách: Chai/ 600ml Sữa Dưỡng Thể Vaseline Total Moisture Cocoa Glow Lotion - Cung cấp độ ẩm suốt 24h với hương coca nồng nàn, ngọt ngào.', 250000, N'duongbody61.png', N'duongbody62.jpg', 260000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (36, 14, N'Kem Dưỡng Da Tay Innisfree 04 April', NULL, 12, N'Kem dưỡng da tay Innisfree phiên bản Tháng Tư có mùi hoa cỏ nhẹ nhàng và tinh tế, giúp da tay trở nên mềm mại mịn màng. Ngoài ra còn giữ được mùi hương rất lâu như dùng nước hoa. Dung tích: 30ML', 70000, N'duongtay11.png', N'duongtay12.jpg', 75000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (37, 14, N'Kem Dưỡng Da Tay Innisfree 05 May', NULL, 12, N'Kem dưỡng da tay Innisfree phiên bản Tháng Năm giúp da tay mềm mại và mịn màng, kết hợp cùng hương trái cây ngọt ngào đầy hấp dẫn, lưu giữ lâu như khi sử dụng nước hoa.', 70000, N'duongtay21.png', N'duongtay22.jpg', 75000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (38, 13, N'Kem Dưỡng Da Tay Innisfree 10 October', NULL, 12, N'Kem dưỡng da tay Innisfree phiên bản Tháng Mười giúp da tay mềm mại và mịn màng, kết hợp cùng mùi hương thiên nhiên rất khác biệt và độc đáo, lưu giữ lâu như khi sử dụng nước hoa.', 70000, N'duongtay31.png', N'duongtay32.jpg', 75000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (39, 13, N'Gel Dưỡng Da Tay Innisfree Green Tea Pure Gel', NULL, 12, N'Dưỡng da tay Innisfree dạng gel chiết xuất trà xanh, giúp dưỡng ẩm và bảo vệ da tay, thấm nhanh và không gây nhờn rít. Dung tích: 50ML', 150000, N'duongtay41.png', N'duongtay42.jpg', 175000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (40, 12, N'Kem Dưỡng Karadium The White Tone Up Cream', NULL, 13, N'Là một bước tiến mới cho dòng sản phẩm dưỡng trắng da, một trong những sản phẩm dưỡng trắng hàng đầu của Karadium. Nhờ thành phần dưỡng ẩm cao giúp da thẩm thấu dưỡng chất từ kem dưỡng để cải thiện tone màu da. Một làn da trắng hồng với chị em bây giờ không còn là mơ ước.', 175000, N'duongmat11.jpg', N'duongmat12.png', 190000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (43, 8, N'Dưỡng Trắng Da SK-II Cellumination Deep Surge EX', NULL, 13, N'Kem dưỡng được tích hợp công nghệ làm trắng bậc nhất của SK-II mang lại ánh sáng tự nhiên cho làn da, giảm thiểu các sắc tố da không đều màu trong thời gian ngắn nhất. Với thành phần chính là Pitera huyền thoại và hỗn hợp hạt làm sáng bóng từ bên trong Aura White Cocktail giúp kiểm soát sự và ngăn chặn quá trình sản xuất Melanin, ngăn ngừa đốm nâu và sạm nám ngay từ đầu, giảm thiểu sự mất cân bằng màu sắc giữa các tế bào, phục hồi hiệu quả các vùng da khô ráp.', 3200000, N'duongmat21.png', N'duongmat22.png', 3600000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (46, 8, N'Kem Dưỡng SK-II R.N.A. Power Airy Milky Lotion', NULL, 13, N'Kem dưỡng SK-II R.N.A Power Airy Milky Lotion chứa các thành phần cao cấp được chọn lọc và ứng dụng công thức tinh chế đặc biệt từ thương hiệu SK-II, trong đó, Hydrolyzad Soy là một dạng protein, nổi bật với khả năng thẩm thấu sâu vào lỗ chân lông, giúp lấp đầy các khoảng trống trong tế bào, từ đó làm căng đầy nếp nhăn, hỗ trợ cải thiện độ đàn hồi và mang lại làn da săn chắc, mịn màng.
', 3580000, N'duongmat31.jpg', N'duongmat32.png', 3700000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (49, 4, N'Set Dưỡng Innisfree Green Tea Skin Care Best Set', NULL, 13, N'Set Dưỡng Da Innisfree NEW Green Tea Skin Care Best Set bao gồm 7 sản phẩm của dòng trà xanh:
Tinh Chất Dưỡng Da Innisfree Green Tea Seed Serum 80ML
Nước Cân Bằng Innisfree Green Tea Balancing Skin EX 200ML
Sữa Dưỡng Innisfree Green Tea Balancing Lotion EX 200ML
Nước Cân Bằng Innisfree Green Tea Balancing Skin EX 25ML
Sữa Dưỡng Innisfree Green Tea Balancing Lotion EX 25ML
Kem Dưỡng Da Innisfree Green Tea Seed Cream 20ML
Mặt Nạ Ngủ Innisfree Green Tea Sleeping Mask 20ML
', 1050000, N'duongmat41.png', N'duongmat42.jpg', 1500000, NULL, NULL)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (51, 4, N'Kem L''Oreal White Perfect SPF17 Day Cream', NULL, 13, N'Kem dưỡng trắng da ban ngày chống nắng SPF 17 PA dưỡng da sáng mịn đều màu. Thành phần chiết xuất tự nhiên, phù hợp mọi loại da, thấy rõ hiệu quả chỉ sau 4 tuần sử dụng. Dung tích: 50ML', 165000, N'duongmat52.jpg', N'duongmat51.jpg', 179000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (52, 5, N'Kem L''Oreal White Perfect Night Cream', NULL, 13, N'Kem dưỡng trắng da ban đêm dưỡng da sáng mịn đều màu. Thành phần chiết xuất tự nhiên, phù hợp mọi loại da, thấy rõ hiệu quả chỉ sau 4 tuần sử dụng. Dung tích: 50ML', 165000, N'duongmat62.jpg', N'duongmat61.jpg', 179000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (54, 6, N'Kem SK-II R.N.A Power Airy Milky Lotion 15G', NULL, 13, N'Với các hoạt chất kích thích sự tái tạo tế bào và phục hồi độ ẩm cho da, kem dưỡng R.N.A Airy Milky Lotion là sự lựa chọn hoàn hảo cho làn da của bạn. Lớp kem mỏng, nhẹ siêu thoáng giúp da bạn luôn rạng rỡ và mềm mịn.', 450000, N'duongmat71.jpg', N'duongmat72.jpg', 460000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (55, 6, N'Kem L''Oreal White Perfect Clinical SPF19 Day Cream', NULL, 13, N'Dưỡng trắng chuyên sâu giúp ngăn chặn quá trình sạm đen da, loại bỏ tế bào sạm nám ra khỏi tế bào da khỏe mạnh, ngăn cản sự hình thành melanin (nguyên nhân gây thâm nám) ngay tại gốc. Dung tích: 50ML', 223000, N'duongmat81.png', N'duongmat82.jpg', 250000, NULL, 0)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (56, 7, N'Kem Bergamo Intensive Snake Wrinkle Care Cream', NULL, 13, N'Dưỡng ẩm chống lão hóa, xóa mờ nếp nhăn, nám trên da, giúp trẻ hóa da. Thẩm thấu nhanh không nhờn rít, thúc đẩy nhanh quá trình tái tạo da. phù hợp với mọi loại da, hiệu quả đặc biệt cho da khô, da thường, da bị chảy xệ. Khối lượng tịnh: 50G', 196000, N'duongmat91.png', N'duongmat92.jpg', 215000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (57, 3, N'Kem Laneige Time Freeze Intensive Cream EX', NULL, 13, N'Bổ sung độ ẩm giúp mang lại làn da săn chắc và mềm mịn, chống lại các dấu hiệu của tuổi tác. Cho bạn làn da khỏe mạnh và tươi trẻ thách thức thời gian. Sản phẩm dành cho mọi loại da. ', 1050000, N'duongmat101.png', N'duongmat102.jpg', 1200000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (58, 3, N'Kem Dưỡng Da Laneige Perfect Renew', NULL, 13, N'Kem dưỡng ẩm giúp dưỡng ẩm, tăng khả năng bảo vệ da và làm mịn da. Thành phần chiết xuất từ thiên nhiên, tăng cường lớp màng ẩm bảo vệ da, mang lại làn da mịn mượt và săn chắc, giúp cải thiện nếp nhăn trên da mặt.', 920000, N'duongmat111.png', N'duongmat112.png', 950000, NULL, 1)
INSERT [dbo].[SanPham] ([MaSP], [MaHieu], [TenSP], [TenAlias], [MaLoai], [MoTa], [DonGia], [Hinh], [Hinh2], [GiaCu], [MaNCC], [SpHot]) VALUES (59, 4, N'Kem Dưỡng Da Innisfree The Green Tea Seed Cream', NULL, 13, N'Chứa 69.5% tinh chất trà xanh hữu cơ dưỡng ẩm cực tốt cho da, giúp gương mặt luôn tươi tắn và mềm mại, không gây nhờn dính. Phục hồi da hư tổn và bảo vệ da khỏi các tác hại từ môi trường.', 160000, N'duongmat122.png', N'duongmat121.jpg', 190000, NULL, 1)
SET IDENTITY_INSERT [dbo].[SanPham] OFF
SET IDENTITY_INSERT [dbo].[ThuongHieu] ON 

INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (1, N'Chloé', N'thuonghieu6.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (2, N'The Face Shop', N'thuonghieu7.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (3, N'Missha', N'thuonghieu15.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (4, N'Chanel', N'thuonghieu4.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (5, N'SK - II', N'thuonghieu5.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (6, N'Amok ', N'thuonghieu1.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (7, N'April Skin', N'thuonghieu2.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (8, N'Laneige', N'thuonghieu8.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (9, N'Vaseline', N'thuonghieu9.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (10, N'Dove', N'thuonghieu10.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (11, N'Lancôme', N'thuonghieu11.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (12, N'Nivea', N'thuonghieu12.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (13, N'innisfree', N'thuonghieu13.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (14, N'Maybelline', N'thuonghieu14.png')
INSERT [dbo].[ThuongHieu] ([MaHieu], [TenHieu], [Hinh]) VALUES (15, N'Dior', N'thuonghieu3.png')
SET IDENTITY_INSERT [dbo].[ThuongHieu] OFF
INSERT [dbo].[TrangThai] ([MaTrangThai], [TenTrangThai], [MoTa]) VALUES (0, N'Chờ xác nhận', N'')
INSERT [dbo].[TrangThai] ([MaTrangThai], [TenTrangThai], [MoTa]) VALUES (1, N'Đang chuẩn bị hàng', NULL)
INSERT [dbo].[TrangThai] ([MaTrangThai], [TenTrangThai], [MoTa]) VALUES (2, N'Đang giao hàng', NULL)
INSERT [dbo].[TrangThai] ([MaTrangThai], [TenTrangThai], [MoTa]) VALUES (3, N'Đã giao hàng', NULL)
SET IDENTITY_INSERT [dbo].[YeuThich] ON 

INSERT [dbo].[YeuThich] ([MaYT], [MaSP], [MaKH], [NgayChon], [MoTa]) VALUES (33, 13, N'dung', CAST(0x0000A9BD009475AF AS DateTime), NULL)
INSERT [dbo].[YeuThich] ([MaYT], [MaSP], [MaKH], [NgayChon], [MoTa]) VALUES (34, 1, N'dung', CAST(0x0000A9BD0094F1DF AS DateTime), NULL)
INSERT [dbo].[YeuThich] ([MaYT], [MaSP], [MaKH], [NgayChon], [MoTa]) VALUES (35, 1, N'trang', CAST(0x0000A9BD009513F3 AS DateTime), NULL)
INSERT [dbo].[YeuThich] ([MaYT], [MaSP], [MaKH], [NgayChon], [MoTa]) VALUES (36, 43, N'dung', CAST(0x0000A9BD00E2A67D AS DateTime), NULL)
SET IDENTITY_INSERT [dbo].[YeuThich] OFF
ALTER TABLE [dbo].[BanBe]  WITH CHECK ADD  CONSTRAINT [FK_BanBe_KhachHang] FOREIGN KEY([MaKH])
REFERENCES [dbo].[KhachHang] ([MaKH])
GO
ALTER TABLE [dbo].[BanBe] CHECK CONSTRAINT [FK_BanBe_KhachHang]
GO
ALTER TABLE [dbo].[BanBe]  WITH CHECK ADD  CONSTRAINT [FK_BanBe_SanPham] FOREIGN KEY([MaSP])
REFERENCES [dbo].[SanPham] ([MaSP])
GO
ALTER TABLE [dbo].[BanBe] CHECK CONSTRAINT [FK_BanBe_SanPham]
GO
ALTER TABLE [dbo].[BinhLuan]  WITH CHECK ADD  CONSTRAINT [FK_BinhLuan_KhachHang] FOREIGN KEY([MaKH])
REFERENCES [dbo].[KhachHang] ([MaKH])
GO
ALTER TABLE [dbo].[BinhLuan] CHECK CONSTRAINT [FK_BinhLuan_KhachHang]
GO
ALTER TABLE [dbo].[BinhLuan]  WITH CHECK ADD  CONSTRAINT [FK_BinhLuan_SanPham] FOREIGN KEY([MaSP])
REFERENCES [dbo].[SanPham] ([MaSP])
GO
ALTER TABLE [dbo].[BinhLuan] CHECK CONSTRAINT [FK_BinhLuan_SanPham]
GO
ALTER TABLE [dbo].[Blog]  WITH CHECK ADD  CONSTRAINT [FK_Blog_LoaiBlog] FOREIGN KEY([MaLoaiBlog])
REFERENCES [dbo].[LoaiBlog] ([MaLoaiBlog])
GO
ALTER TABLE [dbo].[Blog] CHECK CONSTRAINT [FK_Blog_LoaiBlog]
GO
ALTER TABLE [dbo].[ChiTietHD]  WITH CHECK ADD  CONSTRAINT [FK_ChiTietHD_HoaDon] FOREIGN KEY([MaHD])
REFERENCES [dbo].[HoaDon] ([MaHD])
GO
ALTER TABLE [dbo].[ChiTietHD] CHECK CONSTRAINT [FK_ChiTietHD_HoaDon]
GO
ALTER TABLE [dbo].[ChiTietHD]  WITH CHECK ADD  CONSTRAINT [FK_ChiTietHD_SanPham] FOREIGN KEY([MaSP])
REFERENCES [dbo].[SanPham] ([MaSP])
GO
ALTER TABLE [dbo].[ChiTietHD] CHECK CONSTRAINT [FK_ChiTietHD_SanPham]
GO
ALTER TABLE [dbo].[ChuDe]  WITH CHECK ADD  CONSTRAINT [FK_ChuDe_NhanVien] FOREIGN KEY([MaNV])
REFERENCES [dbo].[NhanVien] ([MaNV])
GO
ALTER TABLE [dbo].[ChuDe] CHECK CONSTRAINT [FK_ChuDe_NhanVien]
GO
ALTER TABLE [dbo].[HoaDon]  WITH CHECK ADD  CONSTRAINT [FK_HoaDon_KhachHang] FOREIGN KEY([MaKH])
REFERENCES [dbo].[KhachHang] ([MaKH])
GO
ALTER TABLE [dbo].[HoaDon] CHECK CONSTRAINT [FK_HoaDon_KhachHang]
GO
ALTER TABLE [dbo].[HoaDon]  WITH CHECK ADD  CONSTRAINT [FK_HoaDon_NhanVien] FOREIGN KEY([MaNV])
REFERENCES [dbo].[NhanVien] ([MaNV])
GO
ALTER TABLE [dbo].[HoaDon] CHECK CONSTRAINT [FK_HoaDon_NhanVien]
GO
ALTER TABLE [dbo].[HoaDon]  WITH CHECK ADD  CONSTRAINT [FK_HoaDon_TrangThai] FOREIGN KEY([MaTrangThai])
REFERENCES [dbo].[TrangThai] ([MaTrangThai])
GO
ALTER TABLE [dbo].[HoaDon] CHECK CONSTRAINT [FK_HoaDon_TrangThai]
GO
ALTER TABLE [dbo].[HoiDap]  WITH CHECK ADD  CONSTRAINT [FK_HoiDap_NhanVien] FOREIGN KEY([MaNV])
REFERENCES [dbo].[NhanVien] ([MaNV])
GO
ALTER TABLE [dbo].[HoiDap] CHECK CONSTRAINT [FK_HoiDap_NhanVien]
GO
ALTER TABLE [dbo].[KhoHang]  WITH CHECK ADD  CONSTRAINT [FK_KhoHang_SanPham] FOREIGN KEY([MaSP])
REFERENCES [dbo].[SanPham] ([MaSP])
GO
ALTER TABLE [dbo].[KhoHang] CHECK CONSTRAINT [FK_KhoHang_SanPham]
GO
ALTER TABLE [dbo].[KhuyenMai]  WITH CHECK ADD  CONSTRAINT [FK_KhuyenMai_KhachHang] FOREIGN KEY([MaKH])
REFERENCES [dbo].[KhachHang] ([MaKH])
GO
ALTER TABLE [dbo].[KhuyenMai] CHECK CONSTRAINT [FK_KhuyenMai_KhachHang]
GO
ALTER TABLE [dbo].[PhanCong]  WITH CHECK ADD  CONSTRAINT [FK_PhanCong_NhanVien] FOREIGN KEY([MaNV])
REFERENCES [dbo].[NhanVien] ([MaNV])
GO
ALTER TABLE [dbo].[PhanCong] CHECK CONSTRAINT [FK_PhanCong_NhanVien]
GO
ALTER TABLE [dbo].[PhanCong]  WITH CHECK ADD  CONSTRAINT [FK_PhanCong_PhongBan] FOREIGN KEY([MaPB])
REFERENCES [dbo].[PhongBan] ([MaPB])
GO
ALTER TABLE [dbo].[PhanCong] CHECK CONSTRAINT [FK_PhanCong_PhongBan]
GO
ALTER TABLE [dbo].[PhanQuyen]  WITH CHECK ADD  CONSTRAINT [FK_PhanQuyen_PhongBan] FOREIGN KEY([MaPB])
REFERENCES [dbo].[PhongBan] ([MaPB])
GO
ALTER TABLE [dbo].[PhanQuyen] CHECK CONSTRAINT [FK_PhanQuyen_PhongBan]
GO
ALTER TABLE [dbo].[PhanQuyen]  WITH CHECK ADD  CONSTRAINT [FK_PhanQuyen_TrangWeb] FOREIGN KEY([MaTrang])
REFERENCES [dbo].[TrangWeb] ([MaTrang])
GO
ALTER TABLE [dbo].[PhanQuyen] CHECK CONSTRAINT [FK_PhanQuyen_TrangWeb]
GO
ALTER TABLE [dbo].[SanPham]  WITH CHECK ADD  CONSTRAINT [FK_SanPham_Loai] FOREIGN KEY([MaLoai])
REFERENCES [dbo].[Loai] ([MaLoai])
GO
ALTER TABLE [dbo].[SanPham] CHECK CONSTRAINT [FK_SanPham_Loai]
GO
ALTER TABLE [dbo].[SanPham]  WITH CHECK ADD  CONSTRAINT [FK_SanPham_NhaCungCap] FOREIGN KEY([MaNCC])
REFERENCES [dbo].[NhaCungCap] ([MaNCC])
GO
ALTER TABLE [dbo].[SanPham] CHECK CONSTRAINT [FK_SanPham_NhaCungCap]
GO
ALTER TABLE [dbo].[SanPham]  WITH CHECK ADD  CONSTRAINT [FK_SanPham_ThuongHieu] FOREIGN KEY([MaHieu])
REFERENCES [dbo].[ThuongHieu] ([MaHieu])
GO
ALTER TABLE [dbo].[SanPham] CHECK CONSTRAINT [FK_SanPham_ThuongHieu]
GO
ALTER TABLE [dbo].[ThuongHieu]  WITH CHECK ADD  CONSTRAINT [FK_ThuongHieu_ThuongHieu] FOREIGN KEY([MaHieu])
REFERENCES [dbo].[ThuongHieu] ([MaHieu])
GO
ALTER TABLE [dbo].[ThuongHieu] CHECK CONSTRAINT [FK_ThuongHieu_ThuongHieu]
GO
ALTER TABLE [dbo].[YeuThich]  WITH CHECK ADD  CONSTRAINT [FK_YeuThich_KhachHang] FOREIGN KEY([MaKH])
REFERENCES [dbo].[KhachHang] ([MaKH])
GO
ALTER TABLE [dbo].[YeuThich] CHECK CONSTRAINT [FK_YeuThich_KhachHang]
GO
ALTER TABLE [dbo].[YeuThich]  WITH CHECK ADD  CONSTRAINT [FK_YeuThich_SanPham] FOREIGN KEY([MaSP])
REFERENCES [dbo].[SanPham] ([MaSP])
GO
ALTER TABLE [dbo].[YeuThich] CHECK CONSTRAINT [FK_YeuThich_SanPham]
GO
USE [master]
GO
ALTER DATABASE [MyPham] SET  READ_WRITE 
GO

ALTER TABLE [dbo].[KhachHang] ADD [AuthyId] VARCHAR(50) NULL
GO

ALTER TABLE [dbo].[KhachHang] ADD [PhoneNumber] VARCHAR(50) NULL
GO

ALTER TABLE [dbo].[KhachHang] ADD [PhoneNumberConfirmed] bit DEFAULT (0)
GO
use MyPham
update [KhachHang]
set phonenumberconfirmed=1
go


select*from khachhang
