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
    public class ThuongHieuxController : Controller
    {
        private readonly MyPhamContext _context;

        public ThuongHieuxController(MyPhamContext context)
        {
            _context = context;
        }

        // GET: ThuongHieux
        [Route("[controller]/[action]")]
        public async Task<IActionResult> Index()
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                var myPhamContext = _context.ThuongHieu.Include(t => t.MaHieuNavigation);
                return View(await myPhamContext.ToListAsync());
            }
        }

        // GET: ThuongHieux/Details/5
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

                var thuongHieu = await _context.ThuongHieu
                    .Include(t => t.MaHieuNavigation)
                    .FirstOrDefaultAsync(m => m.MaHieu == id);
                if (thuongHieu == null)
                {
                    return NotFound();
                }

                return View(thuongHieu);
            }
        }

        // GET: ThuongHieux/Create
        [Route("[controller]/[action]")]
        public IActionResult Create()
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                ViewData["MaHieu"] = new SelectList(_context.ThuongHieu, "MaHieu", "MaHieu");
                return View();
            }
        }

        // POST: ThuongHieux/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [Route("[controller]/[action]")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create([Bind("MaHieu,TenHieu,MaSp,Hinh")] ThuongHieu thuongHieu)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (ModelState.IsValid)
                {
                    _context.Add(thuongHieu);
                    await _context.SaveChangesAsync();
                    return RedirectToAction(nameof(Index));
                }
                ViewData["MaHieu"] = new SelectList(_context.ThuongHieu, "MaHieu", "MaHieu", thuongHieu.MaHieu);
                return View(thuongHieu);
            }
        }

        // GET: ThuongHieux/Edit/5
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

                var thuongHieu = await _context.ThuongHieu.FindAsync(id);
                if (thuongHieu == null)
                {
                    return NotFound();
                }
                ViewData["MaHieu"] = new SelectList(_context.ThuongHieu, "MaHieu", "MaHieu", thuongHieu.MaHieu);
                return View(thuongHieu);
            }
        }

        // POST: ThuongHieux/Edit/5
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [Route("[controller]/[action]")]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(int id, [Bind("MaHieu,TenHieu,MaSp,Hinh")] ThuongHieu thuongHieu)
        {
            if (HttpContext.Session.Get<NhanVien>("MaNv") == null)
            {
                return Redirect("/Admin/Login");
            }
            else
            {
                if (id != thuongHieu.MaHieu)
                {
                    return NotFound();
                }

                if (ModelState.IsValid)
                {
                    try
                    {
                        _context.Update(thuongHieu);
                        await _context.SaveChangesAsync();
                    }
                    catch (DbUpdateConcurrencyException)
                    {
                        if (!ThuongHieuExists(thuongHieu.MaHieu))
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
                ViewData["MaHieu"] = new SelectList(_context.ThuongHieu, "MaHieu", "MaHieu", thuongHieu.MaHieu);
                return View(thuongHieu);
            }
        }

        // GET: ThuongHieux/Delete/5
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

                var thuongHieu = await _context.ThuongHieu
                    .Include(t => t.MaHieuNavigation)
                    .FirstOrDefaultAsync(m => m.MaHieu == id);
                if (thuongHieu == null)
                {
                    return NotFound();
                }

                return View(thuongHieu);
            }
        }

        // POST: ThuongHieux/Delete/5
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
                var thuongHieu = await _context.ThuongHieu.FindAsync(id);
                _context.ThuongHieu.Remove(thuongHieu);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
        }

        private bool ThuongHieuExists(int id)
        {
            return _context.ThuongHieu.Any(e => e.MaHieu == id);
        }
    }
}
