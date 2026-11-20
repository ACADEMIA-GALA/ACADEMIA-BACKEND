// --- ADMIN: CLOUDINARY (firma de subida) ---
app.post('/api/admin/sign-upload', authenticateToken, isAdmin, (req, res) => {
  try {
    const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;

    console.log('[sign-upload] cloud_name:', cloudName || 'UNDEFINED');
    console.log('[sign-upload] api_key:', apiKey ? 'DEFINIDO' : 'UNDEFINED');
    console.log('[sign-upload] api_secret:', apiSecret ? 'DEFINIDO' : 'UNDEFINED');

    if (!cloudName || !apiKey || !apiSecret) {
      return res.status(500).json({
        message: 'Cloudinary no está configurado. Revisa .env.'
      });
    }

    const folder = (req.body.folder || 'gala/videos').trim();
    const timestamp = Math.round(Date.now() / 1000);
    const paramsToSign = { timestamp, folder };
    const signature = cloudinary.utils.api_sign_request(paramsToSign, apiSecret);

    console.log('[sign-upload] Firma generada:', signature);
    res.json({ signature, timestamp, folder, api_key: apiKey, cloud_name: cloudName });
  } catch (err) {
    console.error('[sign-upload] Error:', err);
    res.status(500).json({ message: 'Error al firmar', error: err.message });
  }
}); // 🔧 CIERRE CORRECTO

// --- ADMIN: VÍDEOS ---
app.post('/api/admin/stage-videos', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { stage, title, publicId, url } = req.body;
    if (!stage || !title || !publicId || !url) {
      return res.status(400).json({ message: 'Faltan datos' });
    }
    const [result] = await pool.query(
      'INSERT INTO stage_videos (stage, title, cloudinary_public_id, cloudinary_url) VALUES (?, ?, ?, ?)',
      [stage.trim(), title.trim(), publicId, url]
    );
    console.log('[stage-videos] Guardado:', { id: result.insertId, stage, title, publicId });
    res.status(201).json({ id: result.insertId, stage, title, url, publicId });
  } catch (err) {
    console.error('[stage-videos] Error:', err);
    res.status(500).json({ message: 'Error al guardar vídeo' });
  }
});

// --- DELETE ---
app.delete('/api/admin/stage-videos/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const numericId = parseInt(req.params.id, 10);
    if (isNaN(numericId)) return res.status(400).json({ message: 'ID inválido' });

    const [rows] = await pool.query('SELECT * FROM stage_videos WHERE id = ?', [numericId]);
    if (rows.length === 0) return res.status(404).json({ message: 'Vídeo no encontrado' });

    const publicId = rows[0].cloudinary_public_id;
    try {
      await cloudinary.uploader.destroy(publicId, { resource_type: 'video' });
    } catch (cloudErr) {
      console.error('[Cloudinary] Error al eliminar (continúo):', cloudErr);
    }
    await pool.query('DELETE FROM stage_videos WHERE id = ?', [numericId]);
    res.json({ message: 'Vídeo eliminado' });
  } catch (err) {
    console.error('[DELETE] Error:', err);
    res.status(500).json({ message: 'Error al eliminar' });
  }
});

// --- GET VÍDEOS DE ETAPA (con normalización para evitar mismatch) ---
app.get('/api/stage-videos/:stage', authenticateToken, async (req, res) => {
  try {
    // 🔧 FIX: decodificar el parámetro por si llega con %20, y normalizar
    const stageParam = decodeURIComponent(req.params.stage).trim();
    console.log(`[stage-videos] Buscando etapa: "${stageParam}" | user: ${req.user.email} (${req.user.role})`);

    // 🔧 FIX: admin siempre pasa. Alumno: comprobar pago aprobado con comparación case-insensitive y trim
    if (req.user.role !== 'admin') {
      const [payments] = await pool.query(
        `SELECT id FROM payments 
         WHERE user_id = ? 
           AND LOWER(TRIM(stage)) = LOWER(TRIM(?)) 
           AND status = 'aprobado'`,
        [req.user.id, stageParam]
      );
      if (payments.length === 0) {
        console.warn(`[stage-videos] ACCESO DENEGADO a "${stageParam}" para user ${req.user.id}`);
        return res.status(403).json({ message: 'No tienes acceso a esta etapa' });
      }
      console.log(`[stage-videos] Acceso OK a "${stageParam}" para user ${req.user.id}`);
    }

    // 🔧 FIX: misma normalización en la búsqueda de vídeos
    const [videos] = await pool.query(
      `SELECT * FROM stage_videos 
       WHERE LOWER(TRIM(stage)) = LOWER(TRIM(?)) 
       ORDER BY created_at DESC`,
      [stageParam]
    );

    console.log(`[stage-videos] Vídeos encontrados en "${stageParam}": ${videos.length}`);

    res.json(videos.map(v => ({
      id: v.id,
      stage: v.stage,
      title: v.title,
      url: v.cloudinary_url,
      publicId: v.cloudinary_public_id
    })));
  } catch (err) {
    console.error('[stage-videos] Error:', err);
    res.status(500).json({ message: 'Error al obtener vídeos' });
  }
});