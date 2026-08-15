// EDITAR PRODUCTO (SOLO ADMIN) - CAMBIAR NOMBRE, TIPO, PRECIO O IMAGEN (URL O ARCHIVO)
app.put('/api/admin/products/:id', upload.single('productImageFile'), (req, res) => {
  try {
    const { id } = req.params;
    const { name, type, price, imageUrl } = req.body;

    const existing = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
    if (!existing) return res.status(404).json({ error: 'Producto no encontrado.' });

    let finalImageUrl = existing.image_url;

    // Si se subió un archivo desde la PC
    if (req.file) {
      finalImageUrl = '/uploads/' + req.file.filename;
    } else if (imageUrl !== undefined && imageUrl.trim() !== '') {
      // Si se ingresó una URL de imagen
      finalImageUrl = imageUrl.trim();
    }

    const newName = name ? name.trim() : existing.name;
    const newType = type || existing.type;
    const newPrice = price !== undefined ? parseFloat(price) : existing.price;

    db.prepare(`
    UPDATE products
    SET name = ?, type = ?, price = ?, image_url = ?
    WHERE id = ?
    `).run(newName, newType, newPrice, finalImageUrl, id);

    res.json({ message: 'Producto actualizado correctamente.' });
  } catch (err) {
    res.status(500).json({ error: 'Error actualizando producto: ' + err.message });
  }
});
