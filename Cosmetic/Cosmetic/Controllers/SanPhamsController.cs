using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.EntityFrameworkCore;
using Cosmetic.Models;

namespace Cosmetic.Controllers
{
    public class SanPhamsController : Controller
    {
        private readonly MyPhamContext _context;

        public SanPhamsController(MyPhamContext context)
        {
            _context = context;
        }

        // GET: SanPhams
        [Route("[controller]/[action]")]
        public async Task<IActionResult> Index()
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                var myPhamContext = _context.SanPham.Include(s => s.MaLoaiNavigation).Include(s => s.MaNccNavigation);
                return View(await myPhamContext.ToListAsync());
            }
        }

        // GET: SanPhams/Details/5
        [Route("[controller]/[action]")]
        public async Task<IActionResult> Details(int? id)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (id == null)
                {
                    return NotFound();
                }

                var sanPham = await _context.SanPham
                    .Include(s => s.MaLoaiNavigation)
                    .Include(s => s.MaNccNavigation)
                    .FirstOrDefaultAsync(m => m.MaSp == id);
                if (sanPham == null)
                {
                    return NotFound();
                }

                return View(sanPham);
            }
        }

        // GET: SanPhams/Create
        [Route("[controller]/[action]")]
        public IActionResult Create()
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                ViewData["MaLoai"] = new SelectList(_context.Loai, "MaLoai", "MaLoai");
                ViewData["MaNcc"] = new SelectList(_context.NhaCungCap, "MaNcc", "MaNcc");
                return View();
            }
        }

        // POST: SanPhams/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [Route("[controller]/[action]")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("MaSp,TenSp,TenAlias,MaLoai,MoTa,DonGia,Hinh,GiaCu,MaNcc")] SanPham sanPham)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (ModelState.IsValid)
                {
                    _context.Add(sanPham);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                ViewData["MaLoai"] = new SelectList(_context.Loai, "MaLoai", "MaLoai", sanPham.MaLoai);
                ViewData["MaNcc"] = new SelectList(_context.NhaCungCap, "MaNcc", "MaNcc", sanPham.MaNcc);
                return View(sanPham);
            }
        }

        // GET: SanPhams/Edit/5
        [Route("[controller]/[action]")]
        public async Task<IActionResult> Edit(int? id)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (id == null)
                {
                    return NotFound();
                }

                var sanPham = await _context.SanPham.FindAsync(id);
                if (sanPham == null)
                {
                    return NotFound();
                }
                ViewData["MaLoai"] = new SelectList(_context.Loai, "MaLoai", "MaLoai", sanPham.MaLoai);
                ViewData["MaNcc"] = new SelectList(_context.NhaCungCap, "MaNcc", "MaNcc", sanPham.MaNcc);
                return View(sanPham);
            }
        }

        // POST: SanPhams/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [Route("[controller]/[action]")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("MaSp,TenSp,TenAlias,MaLoai,MoTa,DonGia,Hinh,GiaCu,MaNcc")] SanPham sanPham)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (id != sanPham.MaSp)
                {
                    return NotFound();
                }

                if (ModelState.IsValid)
                {
                    try
                    {
                        _context.Update(sanPham);
                        await _context.SaveChangesAsync();
                    }
                    catch (DbUpdateConcurrencyException)
                    {
                        if (!SanPhamExists(sanPham.MaSp))
                        {
                            return NotFound();
                        }
                        else
                        {
                            throw;
                        }
                    }
                    return RedirectToAction(nameof(Index));
                }
                ViewData["MaLoai"] = new SelectList(_context.Loai, "MaLoai", "MaLoai", sanPham.MaLoai);
                ViewData["MaNcc"] = new SelectList(_context.NhaCungCap, "MaNcc", "MaNcc", sanPham.MaNcc);
                return View(sanPham);
            }
        }

        // GET: SanPhams/Delete/5
        [Route("[controller]/[action]")]
        public async Task<IActionResult> Delete(int? id)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (id == null)
                {
                    return NotFound();
                }

                var sanPham = await _context.SanPham
                    .Include(s => s.MaLoaiNavigation)
                    .Include(s => s.MaNccNavigation)
                    .FirstOrDefaultAsync(m => m.MaSp == id);
                if (sanPham == null)
                {
                    return NotFound();
                }

                return View(sanPham);
            }
        }

        // POST: SanPhams/Delete/5
        [Route("[controller]/[action]")]
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirmed(int id)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                var sanPham = await _context.SanPham.FindAsync(id);
                _context.SanPham.Remove(sanPham);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
        }

        private bool SanPhamExists(int id)
        {
            return _context.SanPham.Any(e => e.MaSp == id);
        }
    }
}
