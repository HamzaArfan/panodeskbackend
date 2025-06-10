const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const prisma = new PrismaClient();

const authenticate = async (req, res, next) => {
  try {
    const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access denied. No token provided.'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Get user with all necessary relations
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: {
        organizationMemberships: {
          include: {
            organization: true
          }
        },
        managedOrganizations: true,
        projectReviewers: {
          include: {
            project: {
              include: {
                organization: true
              }
            }
          }
        }
      }
    });

    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid token or user inactive.'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({
      success: false,
      message: 'Invalid token.'
    });
  }
};

const authorize = (requiredRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required.'
      });
    }

    const userRole = req.user.role;

    // Super admin has access to everything
    if (userRole === 'SUPER_ADMIN') {
      return next();
    }

    // Check if user has required role
    if (requiredRoles.includes(userRole)) {
      return next();
    }

    return res.status(403).json({
      success: false,
      message: 'Insufficient permissions.'
    });
  };
};

const checkResourceAccess = (resourceType) => {
  return async (req, res, next) => {
    try {
      const user = req.user;
      const userRole = user.role;

      // Super admin has access to everything
      if (userRole === 'SUPER_ADMIN') {
        return next();
      }

      const resourceId = req.params.id;

      switch (resourceType) {
        case 'organization':
          if (userRole === 'SYSTEM_USER') {
            return next();
          }
          
          // Check if user is manager or member of the organization
          const orgAccess = user.managedOrganizations.some(org => org.id === resourceId) ||
                           user.organizationMemberships.some(membership => membership.organization.id === resourceId);
          
          if (!orgAccess) {
            return res.status(403).json({
              success: false,
              message: 'Access denied to this organization.'
            });
          }
          break;

        case 'project':
          if (userRole === 'SYSTEM_USER') {
            return next();
          }

          const project = await prisma.project.findUnique({
            where: { id: resourceId },
            include: {
              organization: true,
              projectReviewers: true
            }
          });

          if (!project) {
            return res.status(404).json({
              success: false,
              message: 'Project not found.'
            });
          }

          // Organization manager can access projects in their org
          if (userRole === 'ORGANIZATION_MANAGER' && 
              user.managedOrganizations.some(org => org.id === project.organizationId)) {
            return next();
          }

          // Reviewer can access projects they're invited to
          if (userRole === 'REVIEWER' &&
              project.projectReviewers.some(reviewer => reviewer.userId === user.id)) {
            return next();
          }

          return res.status(403).json({
            success: false,
            message: 'Access denied to this project.'
          });

        case 'tour':
          if (userRole === 'SYSTEM_USER') {
            return next();
          }

          const tour = await prisma.tour.findUnique({
            where: { id: resourceId },
            include: {
              project: {
                include: {
                  organization: true,
                  projectReviewers: true
                }
              }
            }
          });

          if (!tour) {
            return res.status(404).json({
              success: false,
              message: 'Tour not found.'
            });
          }

          // Check project access
          const tourProject = tour.project;
          
          // Organization manager can access tours in their org projects
          if (userRole === 'ORGANIZATION_MANAGER' && 
              user.managedOrganizations.some(org => org.id === tourProject.organizationId)) {
            return next();
          }

          // Reviewer can access tours of projects they're invited to
          if (userRole === 'REVIEWER' &&
              tourProject.projectReviewers.some(reviewer => reviewer.userId === user.id)) {
            return next();
          }

          return res.status(403).json({
            success: false,
            message: 'Access denied to this tour.'
          });

        case 'comment':
          // Comments can be accessed by users with access to the related tour
          const comment = await prisma.comment.findUnique({
            where: { id: resourceId },
            include: {
              tour: {
                include: {
                  project: {
                    include: {
                      organization: true,
                      projectReviewers: true
                    }
                  }
                }
              }
            }
          });

          if (!comment) {
            return res.status(404).json({
              success: false,
              message: 'Comment not found.'
            });
          }

          const commentProject = comment.tour.project;

          if (userRole === 'SYSTEM_USER') {
            return next();
          }

          // Organization manager can access comments in their org projects
          if (userRole === 'ORGANIZATION_MANAGER' && 
              user.managedOrganizations.some(org => org.id === commentProject.organizationId)) {
            return next();
          }

          // Reviewer can access comments on tours of projects they're invited to
          if (userRole === 'REVIEWER' &&
              commentProject.projectReviewers.some(reviewer => reviewer.userId === user.id)) {
            return next();
          }

          return res.status(403).json({
            success: false,
            message: 'Access denied to this comment.'
          });

        default:
          return next();
      }

      next();
    } catch (error) {
      console.error('Resource access check error:', error);
      return res.status(500).json({
        success: false,
        message: 'Error checking resource access.'
      });
    }
  };
};

module.exports = {
  authenticate,
  authorize,
  checkResourceAccess
}; 