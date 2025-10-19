const express = require('express');
const { Sequelize, DataTypes, Model, Op } = require('sequelize'); // Import Sequelize
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const validator = require('validator'); // Still useful for email validation
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// --- Database Connection (SQLite) ---
const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: 'localbazaar.sqlite', // This will create a file named localbazaar.sqlite
  logging: false // Set to console.log to see SQL queries
});

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


// --- Models (Sequelize) ---

// Define categories in one place
const offerCategories = ['Clothes', 'Grocery', 'Sweets', 'Restaurants', 'Supermarket', 'Kitchen items'];

// User Model
class User extends Model {
  // Helper method to compare password
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
  hooks: {
    // Hash password before creating a user
    beforeCreate: async (user) => {
      if (user.password) {
        user.password = await bcrypt.hash(user.password, 12);
      }
    }
  }
});

// Offer Model
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
    type: DataTypes.STRING,
    allowNull: false,
    validate: { len: [1, 500] }
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
  modelName: 'Offer'
});

// --- Associations ---
User.hasMany(Offer, { foreignKey: 'createdBy' });
Offer.belongsTo(User, { foreignKey: 'createdBy' });


// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'localbazaar_secret_key';

// Middleware to verify JWT token (no change)
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    // user contains the JWT payload (id, email, shopName)
    req.user = user;
    next();
  });
};

// --- Routes (Rewritten for Sequelize) ---

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { shopName, email, password, category } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ where: { email: email } });
    if (existingUser) {
      return res.status(400).json({ message: 'User with this email already exists' });
    }

    // Create new user (password is hashed by 'beforeCreate' hook)
    const newUser = await User.create({
      shopName,
      email,
      password,
      category
    });

    // Create JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, shopName: newUser.shopName, category: newUser.category },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser.id,
        shopName: newUser.shopName,
        email: newUser.email,
        category: newUser.category
      }
    });
  } catch (error) {
    // Handle validation errors
    if (error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError') {
      return res.status(400).json({ message: error.errors[0].message });
    }
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await User.findOne({ where: { email: email } });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.validPassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, shopName: user.shopName, category: user.category },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        shopName: user.shopName,
        email: user.email,
        category: user.category
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Offer Routes
app.get('/api/offers', async (req, res) => {
  try {
    const { search, category, location } = req.query;

    // Build query
    let whereConditions = [];

    // Only show active offers
    whereConditions.push({ endDate: { [Op.gte]: new Date() } });

    if (search) {
      const searchLike = `%${search}%`;
      whereConditions.push({
        [Op.or]: [
          { title: { [Op.like]: searchLike } },
          { description: { [Op.like]: searchLike } },
          { shopName: { [Op.like]: searchLike } }
        ]
      });
    }

    if (category) {
      const categoryFilter = Array.isArray(category) ? category : [category];
      whereConditions.push({
        [Op.or]: [
          { category: { [Op.in]: categoryFilter } },      // Offer.category matches
          { '$User.category$': { [Op.in]: categoryFilter } } // Associated User.category matches
        ]
      });
    }

    if (location) {
      whereConditions.push({ location: location });
    }

    const offers = await Offer.findAll({
      where: { [Op.and]: whereConditions },
      include: {
        model: User,
        attributes: ['shopName', 'category'] // Join with User to filter by User.category
      },
      order: [
        ['views', 'DESC'],
        ['createdAt', 'DESC']
      ]
    });

    res.json(offers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/offers/:id', async (req, res) => {
  try {
    // findByPk is 'find by primary key', replaces findById
    const offer = await Offer.findByPk(req.params.id);

    if (!offer) {
      return res.status(404).json({ message: 'Offer not found' });
    }

    // Increment view count
    offer.views += 1;
    await offer.save();

    res.json(offer);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/offers', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const {
      shopName,
      category,
      title,
      description,
      location,
      contact,
      startDate,
      endDate
    } = req.body;

    // Create new offer
    const newOffer = await Offer.create({
      shopName,
      category,
      title,
      description,
      location,
      contact,
      startDate: new Date(startDate),
      endDate: new Date(endDate),
      image: req.file ? req.file.filename : '', // Storing filename
      createdBy: req.user.id // From authenticateToken
    });

    res.status(201).json({
      message: 'Offer created successfully',
      offer: newOffer
    });
  } catch (error) {
     if (error.name === 'SequelizeValidationError') {
      return res.status(400).json({ message: error.errors[0].message });
    }
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.put('/api/offers/:id', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    // Find offer
    const offer = await Offer.findByPk(req.params.id);

    if (!offer) {
      return res.status(404).json({ message: 'Offer not found' });
    }

    // Check if user owns the offer
    if (offer.createdBy !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to update this offer' });
    }

    // Update offer data
    const updatedData = req.body;

    if (req.file) {
      // Delete old image
      if (offer.image && fs.existsSync(path.join(uploadsDir, offer.image))) {
        fs.unlinkSync(path.join(uploadsDir, offer.image));
      }
      updatedData.image = req.file.filename;
    }

    // Update the offer in the database
    await offer.update(updatedData);

    res.json({
      message: 'Offer updated successfully',
      offer
    });
  } catch (error) {
    if (error.name === 'SequelizeValidationError') {
      return res.status(400).json({ message: error.errors[0].message });
    }
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/api/offers/:id', authenticateToken, async (req, res) => {
  try {
    // Find offer
    const offer = await Offer.findByPk(req.params.id);

    if (!offer) {
      return res.status(404).json({ message: 'Offer not found' });
    }

    // Check if user owns the offer
    if (offer.createdBy !== req.user.id) {
      return res.status(403).json({ message: 'Not authorized to delete this offer' });
    }

    // Delete image if exists
    if (offer.image && fs.existsSync(path.join(uploadsDir, offer.image))) {
      fs.unlinkSync(path.join(uploadsDir, offer.image));
    }

    await offer.destroy();

    res.json({ message: 'Offer deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get user's offers
app.get('/api/user/offers', authenticateToken, async (req, res) => {
  try {
    const offers = await Offer.findAll({
      where: { createdBy: req.user.id },
      order: [['createdAt', 'DESC']]
    });

    res.json(offers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get categories
app.get('/api/categories', (req, res) => {
  try {
    // Send the hardcoded list
    res.json(offerCategories);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// --- UPDATED LOCATIONS ENDPOINT ---
app.get('/api/locations', async (req, res) => {
  try {
    // Find all distinct locations
    const dbLocations = await Offer.findAll({
      attributes: [[Sequelize.fn('DISTINCT', Sequelize.col('location')), 'location']]
    });

    let locations = dbLocations.map(l => l.location);

    // If no locations are in the DB, provide some examples
    if (locations.length === 0) {
      locations = ['Karur', 'Chennai', 'Coimbatore', 'Madurai'];
    }

    res.json(locations);

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});
// --- END UPDATED ENDPOINT ---

// Get user stats
app.get('/api/user/stats', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    const totalOffers = await Offer.count({ where: { createdBy: userId } });

    const activeOffers = await Offer.count({
      where: {
        createdBy: userId,
        endDate: { [Op.gte]: new Date() }
      }
    });

    const totalViews = await Offer.sum('views', { where: { createdBy: userId } });

    res.json({
      totalOffers: totalOffers || 0,
      activeOffers: activeOffers || 0,
      totalViews: totalViews || 0
    });
  } catch (error)
 {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(5G0).json({ message: 'Something went wrong!' });
});

// --- Serve Frontend ---
// This must be after all your API routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Start Server ---
// We sync the database first, then start the server
async function startServer() {
  try {
    // This creates/updates tables based on your models
    await sequelize.sync({ alter: true });
    console.log('Database synced successfully.');

    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Unable to connect to the database:', error);
  }
}

// Run the server
startServer();