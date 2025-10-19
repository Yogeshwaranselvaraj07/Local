const express = require('express');
// --- MODIFIED: Removed sqlite3 requirement, added Op from sequelize ---
const { Sequelize, DataTypes, Model, Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const validator = require('validator');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// --- MODIFIED: Database Connection (PostgreSQL using DATABASE_URL) ---
if (!process.env.DATABASE_URL) {
  console.error("FATAL ERROR: DATABASE_URL environment variable is not set.");
  process.exit(1); // Exit if the database URL isn't configured
}

const sequelize = new Sequelize(process.env.DATABASE_URL, {
  dialect: 'postgres', // Specify PostgreSQL dialect
  protocol: 'postgres',
  logging: false, // Set to console.log to see SQL queries
  dialectOptions: {
    // Required for Render/Neon connection using SSL
    ssl: {
      require: true,
      rejectUnauthorized: false // Necessary for self-signed certificates or specific cloud provider setups
    }
  },
});
// --- END MODIFIED SECTION ---

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// File upload configuration (no changes)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: {
    fileSize: parseInt(process.env.MAX_FILE_SIZE) || 5000000 // 5MB default
  },
  fileFilter: fileFilter
});


// --- Models (Sequelize - Definitions remain the same) ---

const offerCategories = ['Clothes', 'Grocery', 'Sweets', 'Restaurants', 'Supermarket', 'Kitchen items'];

class User extends Model {
  async validPassword(password) {
    return await bcrypt.compare(password, this.password);
  }
}

User.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  shopName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      notEmpty: { msg: 'Shop name is required' },
      len: [1, 100]
    }
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: { msg: 'Email must be unique' },
    validate: {
      isEmail: { msg: 'Please provide a valid email' }
    }
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [6, 255]
    }
  },
  category: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
        notEmpty: { msg: 'Shop category is required' },
        isIn: {
            args: [offerCategories],
            msg: 'Invalid category'
        }
    }
  }
}, {
  sequelize,
  modelName: 'User',
  // Sequelize automatically adds createdAt and updatedAt columns
  // If your PostgreSQL table names need double quotes (e.g., case sensitivity), add:
  // freezeTableName: true,
  // tableName: '"Users"' // Example if needed
  hooks: {
    beforeCreate: async (user) => {
      if (user.password) {
        user.password = await bcrypt.hash(user.password, 12);
      }
    }
  }
});

class Offer extends Model {}

Offer.init({
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  shopName: {
    type: DataTypes.STRING,
    allowNull: false
  },
  category: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      isIn: {
        args: [offerCategories],
        msg: 'Invalid category'
      }
    }
  },
  title: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: { len: [1, 100] }
  },
  description: {
    type: DataTypes.TEXT, // Using TEXT for potentially longer descriptions in PostgreSQL
    allowNull: false,
    validate: { len: [1, 500] } // Validation remains
  },
  location: {
    type: DataTypes.STRING,
    allowNull: false
  },
  contact: {
    type: DataTypes.STRING,
    allowNull: false
  },
  startDate: {
    type: DataTypes.DATE,
    allowNull: false
  },
  endDate: {
    type: DataTypes.DATE,
    allowNull: false
  },
  image: {
    type: DataTypes.STRING,
    defaultValue: ''
  },
  views: {
    type: DataTypes.INTEGER,
    defaultValue: 0
  }
  // createdBy will be added via association
}, {
  sequelize,
  modelName: 'Offer',
  // If your PostgreSQL table names need double quotes, add:
  // freezeTableName: true,
  // tableName: '"Offers"' // Example if needed
});

// --- Associations (Remain the same) ---
// Define association key explicitly for clarity
User.hasMany(Offer, { foreignKey: 'createdBy', as: 'offers' });
Offer.belongsTo(User, { foreignKey: 'createdBy', as: 'user' });


// JWT Secret (Remains the same)
const JWT_SECRET = process.env.JWT_SECRET || 'localbazaar_secret_key_dev_only'; // Use a strong secret in production!

// Middleware to verify JWT token (Remains the same)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access token required' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user; // Contains { id, email, shopName, category } from the token
    next();
  });
};

// --- Routes (Mostly remain the same, logic handled by Sequelize) ---

// Auth Routes (No changes needed)
app.post('/api/auth/register', async (req, res) => {
  try {
    const { shopName, email, password, category } = req.body;
    const existingUser = await User.findOne({ where: { email: email } });
    if (existingUser) return res.status(400).json({ message: 'User with this email already exists' });
    const newUser = await User.create({ shopName, email, password, category });
    const token = jwt.sign({ id: newUser.id, email: newUser.email, shopName: newUser.shopName, category: newUser.category }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ message: 'User registered successfully', token, user: { id: newUser.id, shopName: newUser.shopName, email: newUser.email, category: newUser.category }});
  } catch (error) {
    if (error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError') return res.status(400).json({ message: error.errors[0].message });
    console.error("Register Error:", error); res.status(500).json({ message: 'Server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email: email } });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });
    const isMatch = await user.validPassword(password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, shopName: user.shopName, category: user.category }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful', token, user: { id: user.id, shopName: user.shopName, email: user.email, category: user.category }});
  } catch (error) { console.error("Login Error:", error); res.status(500).json({ message: 'Server error during login' }); }
});

// Offer Routes (Using iLike for Postgres search)
app.get('/api/offers', async (req, res) => {
  try {
    const { search, category, location } = req.query;
    let whereConditions = [{ endDate: { [Op.gte]: new Date() } }];
    if (search) {
      const searchLike = `%${search}%`;
      whereConditions.push({ [Op.or]: [
          { title: { [Op.iLike]: searchLike } }, // Case-insensitive
          { description: { [Op.iLike]: searchLike } },
          { shopName: { [Op.iLike]: searchLike } }
        ]});
    }
    if (category) {
      const categoryFilter = Array.isArray(category) ? category : [category];
      whereConditions.push({ [Op.or]: [
          { category: { [Op.in]: categoryFilter } },
          { '$user.category$': { [Op.in]: categoryFilter } } // Use the alias 'user' defined in include
        ]});
    }
    if (location) whereConditions.push({ location: location });

    const offers = await Offer.findAll({
      where: { [Op.and]: whereConditions },
      include: { model: User, as: 'user', attributes: ['shopName', 'category'] }, // Use alias 'user'
      order: [['views', 'DESC'], ['createdAt', 'DESC']]
    });
    res.json(offers);
  } catch (error) { console.error("Get Offers Error:", error); res.status(500).json({ message: 'Server error fetching offers' }); }
});

app.get('/api/offers/:id', async (req, res) => {
  try {
    const offerId = parseInt(req.params.id, 10); // Ensure ID is an integer
    if (isNaN(offerId)) return res.status(400).json({ message: 'Invalid offer ID' });
    const offer = await Offer.findByPk(offerId);
    if (!offer) return res.status(404).json({ message: 'Offer not found' });
    // Increment view count using Sequelize's increment method
    await offer.increment('views', { by: 1 });
    // Re-fetch offer to get updated view count if needed, or just send old count + 1
    // For simplicity, we send the incremented object directly (may not reflect concurrent updates)
    offer.views += 1;
    res.json(offer);
  } catch (error) { console.error("Get Offer By ID Error:", error); res.status(500).json({ message: 'Server error fetching offer details' }); }
});

app.post('/api/offers', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const { shopName, category, title, description, location, contact, startDate, endDate } = req.body;
    // Basic validation for dates
    if (!startDate || !endDate || new Date(startDate) >= new Date(endDate)) {
        return res.status(400).json({ message: 'Valid start and end dates are required, and start date must be before end date.' });
    }
    const newOffer = await Offer.create({
      shopName, category, title, description, location, contact,
      startDate: new Date(startDate), endDate: new Date(endDate),
      image: req.file ? req.file.filename : '', createdBy: req.user.id
    });
    res.status(201).json({ message: 'Offer created successfully', offer: newOffer });
  } catch (error) {
     if (error.name === 'SequelizeValidationError') return res.status(400).json({ message: error.errors.map(e => e.message).join(', ') });
     console.error("Create Offer Error:", error); res.status(500).json({ message: 'Server error creating offer' });
  }
});

app.put('/api/offers/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const offerId = parseInt(req.params.id, 10);
    if (isNaN(offerId)) return res.status(400).json({ message: 'Invalid offer ID' });
    const offer = await Offer.findByPk(offerId);
    if (!offer) return res.status(404).json({ message: 'Offer not found' });
    if (offer.createdBy !== req.user.id) return res.status(403).json({ message: 'Not authorized' });

    const { startDate, endDate } = req.body;
    if (startDate && endDate && new Date(startDate) >= new Date(endDate)) {
        return res.status(400).json({ message: 'Start date must be before end date.' });
    }

    const updatedData = req.body;
    if (req.file) {
      if (offer.image && fs.existsSync(path.join(uploadsDir, offer.image))) fs.unlinkSync(path.join(uploadsDir, offer.image));
      updatedData.image = req.file.filename;
    } else {
      // Prevent image field from being set to null if no file is uploaded during update
      delete updatedData.image;
    }
    await offer.update(updatedData);
    res.json({ message: 'Offer updated successfully', offer }); // Send back the updated offer
  } catch (error) {
    if (error.name === 'SequelizeValidationError') return res.status(400).json({ message: error.errors.map(e => e.message).join(', ') });
    console.error("Update Offer Error:", error); res.status(500).json({ message: 'Server error updating offer' });
  }
});

app.delete('/api/offers/:id', authenticateToken, async (req, res) => {
  try {
    const offerId = parseInt(req.params.id, 10);
    if (isNaN(offerId)) return res.status(400).json({ message: 'Invalid offer ID' });
    const offer = await Offer.findByPk(offerId);
    if (!offer) return res.status(404).json({ message: 'Offer not found' });
    if (offer.createdBy !== req.user.id) return res.status(403).json({ message: 'Not authorized' });
    if (offer.image && fs.existsSync(path.join(uploadsDir, offer.image))) fs.unlinkSync(path.join(uploadsDir, offer.image));
    await offer.destroy();
    res.json({ message: 'Offer deleted successfully' });
  } catch (error) { console.error("Delete Offer Error:", error); res.status(500).json({ message: 'Server error deleting offer' }); }
});

app.get('/api/user/offers', authenticateToken, async (req, res) => {
  try {
    const offers = await Offer.findAll({ where: { createdBy: req.user.id }, order: [['createdAt', 'DESC']] });
    res.json(offers);
  } catch (error) { console.error("Get User Offers Error:", error); res.status(500).json({ message: "Server error fetching user's offers" }); }
});

app.get('/api/categories', (req, res) => {
  try { res.json(offerCategories); }
  catch (error) { console.error("Get Categories Error:", error); res.status(500).json({ message: 'Server error fetching categories' }); }
});

app.get('/api/locations', async (req, res) => {
  try {
    const dbLocations = await sequelize.query(
      // Use double quotes for case-sensitive table names if needed in PostgreSQL
      'SELECT DISTINCT location FROM "Offers" WHERE location IS NOT NULL AND location != \'\' ORDER BY location ASC',
      { type: Sequelize.QueryTypes.SELECT }
    );
    let locations = dbLocations.map(l => l.location);
    if (locations.length === 0) locations = ['Karur', 'Chennai', 'Coimbatore', 'Madurai']; // Default examples
    res.json(locations);
  } catch (error) { console.error("Get Locations Error:", error); res.status(500).json({ message: 'Server error fetching locations' }); }
});

app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const totalOffers = await Offer.count({ where: { createdBy: userId } });
    const activeOffers = await Offer.count({ where: { createdBy: userId, endDate: { [Op.gte]: new Date() } } });
    const totalViews = await Offer.sum('views', { where: { createdBy: userId } });
    res.json({ totalOffers: totalOffers || 0, activeOffers: activeOffers || 0, totalViews: totalViews || 0 });
  } catch (error) { console.error("Get User Stats Error:", error); res.status(500).json({ message: 'Server error fetching user stats' }); }
});

// Error handling middleware (Remains the same)
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// --- Serve Frontend (Remains the same) ---
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Start Server ---
async function startServer() {
  try {
    await sequelize.authenticate(); // Test the connection
    console.log('Database connection established successfully.');

    // Sync models
    // Use { alter: true } only in development if you modify columns often.
    // In production, use migrations for schema changes.
    await sequelize.sync({ alter: process.env.NODE_ENV !== 'production' });
    console.log('Database synced successfully.');

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Unable to connect to the database or sync:', error);
    process.exit(1); // Exit if DB connection/sync fails
  }
}

startServer();
